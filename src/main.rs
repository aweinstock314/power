extern crate byteorder;
extern crate crypto;
extern crate futures;
extern crate hyper;
extern crate openssl;
extern crate openssl_sys;
extern crate rayon;
extern crate ring;
extern crate rustc_serialize;
extern crate tokio_core;
extern crate tokio_io;
extern crate url;

use byteorder::{ByteOrder, LittleEndian};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use futures::{Future, future, Stream};
use hyper::StatusCode;
use hyper::server::{Service, Request, Response, Http};
use rayon::prelude::*;
use rayon::{current_num_threads, RayonFuture};
use rustc_serialize::hex::{FromHex, ToHex};
use std::fmt::Write;
use std::io;
use std::sync::{Arc, atomic};
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use tokio_io::{AsyncRead, AsyncWrite};
use url::Url;

fn detect_hup<I: AsyncRead + AsyncWrite>(io: I) -> (DetectHUP<I>, futures::sync::oneshot::Receiver<()>) {
    let (sender, receiver) = futures::sync::oneshot::channel();
    (DetectHUP { io: io, sender: Some(sender) }, receiver)
}
struct DetectHUP<I> {
    io: I,
    sender: Option<futures::sync::oneshot::Sender<()>>
}
impl<I> DetectHUP<I> {
    fn abortlogic<T: std::fmt::Debug>(&mut self, x: Result<T, io::Error>) -> Result<T, io::Error> {
        println!("{:?}", x);
        if let Err(ref e) = x {
            println!("e.kind {:?}", e.kind());
            if e.kind() == io::ErrorKind::ConnectionReset {
                let _ = self.sender.take().map(|sender| sender.send(()));
            }
        }
        x
    }
}
// TODO: more delegation (all Read+Write+AsyncRead+AsyncWrite methods) for efficiency
impl<I: AsyncRead> io::Read for DetectHUP<I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let tmp = self.io.read(buf);
        self.abortlogic(tmp)
    }
}
impl<I: AsyncRead> AsyncRead for DetectHUP<I> {}

impl<I: AsyncWrite> io::Write for DetectHUP<I> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let tmp = self.io.write(buf);
        self.abortlogic(tmp)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}
impl<I: AsyncWrite> AsyncWrite for DetectHUP<I> {
    fn shutdown(&mut self) -> futures::Poll<(), io::Error> {
        self.io.shutdown()
    }
}

#[allow(dead_code)]
#[inline(always)]
fn rustcrypto_sha256(x: [u8; 8]) -> [u8; 32] {
/*
$ time curl localhost:3000/sha256?mask=$(python -c 'print "00"*29+"ff"*3')\&goal=$(python -c 'print "00"*29+"deadbe"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m3.056s
user    0m0.032s
sys     0m0.004s
*/
    let mut tmpoutput = [0; 32];
    let mut hasher = Sha256::new();
    hasher.input(&x);
    hasher.result(&mut tmpoutput);
    tmpoutput
}
#[allow(dead_code)]
#[inline(always)]
fn openssl_sha256(x: [u8; 8]) -> [u8; 32] {
/*
$ time curl localhost:3000/sha256?mask=$(python -c 'print "00"*29+"ff"*3')\&goal=$(python -c 'print "00"*29+"deadbe"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m4.046s
user    0m0.036s
sys     0m0.016s
*/
    use openssl::hash::{hash, MessageDigest};
    let mut output = [0; 32];
    output.copy_from_slice(&hash(MessageDigest::sha256(), &x).unwrap()[0..32]);
    output
}
#[allow(dead_code)]
#[inline(always)]
fn openssl_sys_sha256(x: [u8; 8]) -> [u8; 32] {
/*
$ time curl localhost:3000/sha256?mask=$(python -c 'print "00"*29+"ff"*3')\&goal=$(python -c 'print "00"*29+"deadbe"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m3.771s
user    0m0.020s
sys     0m0.004s
*/
    let mut output = [0; 32];
    unsafe {
        openssl_sys::init();
        let md = openssl_sys::EVP_sha256();
        let ctx = openssl_sys::EVP_MD_CTX_create();
        openssl_sys::EVP_DigestInit_ex(ctx, md, 0 as *mut _);
        openssl_sys::EVP_DigestUpdate(ctx, x.as_ptr() as *const _, x.len());
        openssl_sys::EVP_DigestFinal(ctx, output.as_mut_ptr() as *mut _, 0 as *mut _);
        openssl_sys::EVP_MD_CTX_destroy(ctx);
    }
    output
}
#[allow(dead_code)]
#[inline(always)]
fn ring_sha256(x: [u8; 8]) -> [u8; 32] {
/*
$ time curl localhost:3000/sha256?mask=$(python -c 'print "00"*29+"ff"*3')\&goal=$(python -c 'print "00"*29+"deadbe"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m2.133s
user    0m0.012s
sys     0m0.008s
*/
    use ring::digest;
    let mut output = [0; 32];
    output.copy_from_slice(&digest::digest(&digest::SHA256, &x).as_ref()[0..32]);
    output
}

fn proofofwork<F>(mask: Vec<u8>, goal: Vec<u8>, done: Arc<atomic::AtomicBool>, f: F) -> RayonFuture<(String, String), hyper::Error> where
    F: Fn([u8; 8]) -> [u8; 32] + Send + Sync + 'static {
    assert_eq!(mask.len(), goal.len());
    assert_eq!(mask.len(), 32);
    rayon::spawn_future_async(future::lazy(move || {
        let mask = mask;
        let mask = &mask[..];
        let goal = goal;
        let goal = &goal[..];
        let f = |x: u64| {
            if done.load(atomic::Ordering::Relaxed) {
                return None;
            }
            let mut tmpinput = [0; 8];
            LittleEndian::write_u64(&mut tmpinput, x);
            // TODO: efficient alphanumeric hashes
            //if !tmpinput.iter().all(|&c| (c as char).is_alphanumeric()) { return None; }
            let tmpoutput = f(tmpinput);
            if mask.iter().zip(goal).zip(tmpoutput.iter()).all(|((m, g), o)| (m & o) == (m & g)) {
                //return Some((std::str::from_utf8(&tmpinput).unwrap().into(), hasher.result_str()));
                return Some((tmpinput.to_hex(), f(tmpinput).to_hex()));
            }
            None
        };
        Ok((0..2u64.pow(63)).into_par_iter().filter_map(f).find_any(|_| true).unwrap())
    }))
}

const HELP_MSG: &'static str = "Usage examples:
$ time curl localhost:3000/sha256?mask=$(python -c 'print \"00\"*29+\"ff\"*3')\\&goal=$(python -c 'print \"00\"*29+\"deadbe\"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m3.049s
user    0m0.040s
sys     0m0.008s
$ python -c 'import sys; sys.stdout.write(\"159a360000000000\".decode(\"hex\"))' | sha256sum
9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe  -
$ python
>>> import requests
>>> requests.get('http://localhost:3000/sha256', params={'mask': '00'+'ff'*3+'00'*28, 'goal': '00badc0d'+'00'*28}).text
u'78a3170000000000 has hash fcbadc0d5856bb6eea467a236218eb5e16017a1636e335e2946618feb0aae620\\n'
>>> requests.get('http://localhost:3000/sha256', params={'mask': 'ff'*4+'00'*28, 'goal': '00abcdef'+'00'*28}).text
u'c72b530200000040 has hash 00abcdef83801fd557e1740187560ac4fdc557645e175f5faeb407e54a2d9958\\n'

Intended general usage (more algos will be added later):
GET /sha256?mask=<some 32 byte hex encoded mask>&goal=<some 32 byte hex encoded goal>";

struct POWService(Arc<atomic::AtomicBool>);
impl Service for POWService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=hyper::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        match req.method() {
            &hyper::Get => (),
            _ => return Box::new(future::ok(Response::new().with_status(StatusCode::NotFound))),
        }
        match req.path() {
            "/sha256" => { powserver(req, self.0.clone()) }
            _ => Box::new(future::ok(Response::new().with_body(HELP_MSG.as_bytes())))
        }
    }
}

fn fmt_error_to_hyper_error(e: std::fmt::Error) -> hyper::Error {
    let tmp: std::io::Error = std::io::Error::new(std::io::ErrorKind::Other, e);
    tmp.into()
}

fn powserver(req: Request, done: Arc<atomic::AtomicBool>) -> Box<Future<Item=Response, Error=hyper::Error>> {
    let base_url = Url::parse("http://foo").unwrap();
    println!("{:?}", req.uri());
    println!("{:?}", req.headers());
    if let Ok(url) = Url::options().base_url(Some(&base_url)).parse(&req.uri().as_ref()) {
        let mut mask = None;
        let mut goal = None;
        for (k, v) in url.query_pairs() {
            if k == "mask" && v.len() == 32*2 {
                mask = v.from_hex().ok();
            }
            if k == "goal" && v.len() == 32*2 {
                goal = v.from_hex().ok();
            }
        }
        println!("mask: {:?}\ngoal: {:?}", mask.clone().map(|x| x.to_hex()), goal.clone().map(|x| x.to_hex()));
        if let (Some(mask), Some(goal)) = (mask, goal) {
            let mut resp = String::new();
            return Box::new(proofofwork(mask, goal, done.clone(), ring_sha256).and_then(|(x, hash)| {
                println!("sending preimage {}", x);
                if let Err(e) = writeln!(resp, "{} has hash {}", x, hash) {
                    return Err(fmt_error_to_hyper_error(e));
                }
                Ok(Response::new().with_body(resp))
            }));
        }
    }
    Box::new(future::ok(Response::new().with_body(HELP_MSG.as_bytes())))
}

fn main() {
    if let Some(Ok(port)) = std::env::args().nth(1).map(|x| x.parse::<u16>()) {
        println!("current_num_threads: {}", current_num_threads());
        let bindaddr = ("0.0.0.0".parse::<std::net::IpAddr>().unwrap(), port);
        /*Http::new().bind(&bindaddr.into(), || Ok(POWService)).expect("Failed to bind server")
            .run().expect("Fatal error while running the server");*/
        let http = Http::new();
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let listener = TcpListener::bind(&bindaddr.into(), &handle).unwrap();
        core.run(listener.incoming().for_each(|(sock, addr)| {
            let (sock, hup) = detect_hup(sock);
            let done = Arc::new(atomic::AtomicBool::new(false));
            http.bind_connection(&handle, sock, addr, POWService(done.clone()));
            handle.spawn(hup.and_then(move |()| { done.store(true, atomic::Ordering::Relaxed); Ok(()) }).map_err(|_| ()));
            Ok(())
        })).unwrap();
    } else {
        println!("Expecting the port as the first argument.");
    }
}

#[test]
fn test_pow() {
    println!("current_num_threads: {}", current_num_threads());
    println!("POW: {:?}", proofofwork(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff",
                                      b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\x85\xbd"));
}
