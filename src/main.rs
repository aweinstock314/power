#![cfg_attr(feature="cargo-clippy", allow(inline_always))]
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
extern crate tokio_proto;
extern crate url;

use byteorder::{ByteOrder, LittleEndian};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use futures::{Future, future, Stream, stream, Sink};
use hyper::StatusCode;
use hyper::server::{Service, Request, Response, Http};
use rayon::prelude::*;
use rustc_serialize::hex::{FromHex, ToHex};
use std::{io, ptr};
use std::sync::{Arc, atomic};
use std::time::Duration;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Core, Handle, Timeout};
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
        //println!("{:?}", x);
        if let Err(ref e) = x {
            println!("e.kind {:?}", e.kind());
            if e.kind() == io::ErrorKind::BrokenPipe {
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

/*struct InjectZeroLengthReads<P>(P, Duration);
impl<B: AsRef<[u8]>+'static> InjectZeroLengthReads<Http<B>> {
    fn bind_connection<S, I, Bd>(&self, handle: &Handle, io: I, remote_service: std::net::SocketAddr, service: S) where
        S: Service<Request=Request, Response=Response<Bd>, Error=hyper::Error> + 'static,
        Bd: Stream<Item=B, Error=hyper::Error> + 'static,
        I: AsyncRead + AsyncWrite + 'static {
        println!("IZLR bind_connection");
        self.0.bind_connection(handle, io, remote_service, service)
    }
}
impl<T: 'static, P: tokio_proto::pipeline::ServerProto<T>> tokio_proto::pipeline::ServerProto<T> for InjectZeroLengthReads<P> where
    P::Request: std::fmt::Debug,
    P::Response: std::fmt::Debug {
    type Request = P::Request;
    type Response = P::Response;
    type Transport = IZLRTransport<T, P>;
    type BindTransport = Box<Future<Item=Self::Transport, Error=io::Error>>;
    fn bind_transport(&self, io: T) -> Self::BindTransport {
        use futures::IntoFuture;
        println!("IZLR bind_transport");
        Box::new(self.0.bind_transport(io).into_future().map(IZLRTransport))
    }
}
struct IZLRTransport<T: 'static, P: tokio_proto::pipeline::ServerProto<T>>(P::Transport);
impl<T, P: tokio_proto::pipeline::ServerProto<T>> Stream for IZLRTransport<T, P> where
    P::Request: std::fmt::Debug {
    type Item = P::Request;
    type Error = io::Error;
    fn poll(&mut self) -> futures::Poll<Option<Self::Item>, Self::Error> {
        let tmp = self.0.poll();
        println!("IZLRTransport::poll {:?}", tmp);
        tmp
    }
}

impl<T, P: tokio_proto::pipeline::ServerProto<T>> Sink for IZLRTransport<T, P> where
    P::Response: std::fmt::Debug {
    type SinkItem = P::Response;
    type SinkError = io::Error;
    fn start_send(&mut self, item: Self::SinkItem) -> futures::StartSend<Self::SinkItem, Self::SinkError> {
        let tmp = self.0.start_send(item);
        println!("IZLRTransport::start_send {:?}", tmp);
        tmp
    }
    fn poll_complete(&mut self) -> futures::Poll<(), Self::SinkError> {
        let tmp = self.0.poll_complete();
        println!("IZLRTransport::poll_complete {:?}", tmp);
        tmp
    }
}*/

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

real    0m3.427s
user    0m0.040s
sys     0m0.008s
*/
    let mut output = [0; 32];
    thread_local!(static INIT: () = openssl_sys::init());
    thread_local!(static MD: *const openssl_sys::EVP_MD = unsafe { openssl_sys::EVP_sha256() });
    thread_local!(static CTX: *mut openssl_sys::EVP_MD_CTX = unsafe { openssl_sys::EVP_MD_CTX_create() }); // TODO: RAII wrapper
    unsafe {
        INIT.with(|&()| { MD.with(|&md| { CTX.with(|&ctx| {
            openssl_sys::EVP_DigestInit_ex(ctx, md, ptr::null_mut());
            openssl_sys::EVP_DigestUpdate(ctx, x.as_ptr() as *const _, x.len());
            openssl_sys::EVP_DigestFinal(ctx, output.as_mut_ptr() as *mut _, ptr::null_mut());
        })})});
    }
    output
}
#[allow(dead_code)]
#[inline(always)]
fn ring_sha256(x: &[u8]) -> [u8; 32] {
/*
$ time curl localhost:3000/sha256?mask=$(python -c 'print "00"*29+"ff"*3')\&goal=$(python -c 'print "00"*29+"deadbe"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m2.133s
user    0m0.012s
sys     0m0.008s
*/
    use ring::digest;
    let mut output = [0; 32];
    output.copy_from_slice(&digest::digest(&digest::SHA256, x).as_ref()[0..32]);
    output
}
#[allow(dead_code)]
#[inline(always)]
fn openssl_sys_md5(x: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    thread_local!(static INIT: () = openssl_sys::init());
    thread_local!(static MD: *const openssl_sys::EVP_MD = unsafe { openssl_sys::EVP_md5() });
    thread_local!(static CTX: *mut openssl_sys::EVP_MD_CTX = unsafe { openssl_sys::EVP_MD_CTX_create() }); // TODO: RAII wrapper
    unsafe {
        INIT.with(|&()| { MD.with(|&md| { CTX.with(|&ctx| {
            openssl_sys::EVP_DigestInit_ex(ctx, md, ptr::null_mut());
            openssl_sys::EVP_DigestUpdate(ctx, x.as_ptr() as *const _, x.len());
            openssl_sys::EVP_DigestFinal(ctx, output.as_mut_ptr() as *mut _, ptr::null_mut());
        })})});
    }
    output
}

macro_rules! parallel_cartesian_product {
    ($f:expr, $g:expr) => { ($f)().flat_map(move |a| ($g)().map(move |b| (a,b))) };
    ($f:expr, $g:expr, $($h:expr),+) => {
        parallel_cartesian_product!(move || parallel_cartesian_product!($f, $g), $($h),+)
    };
}

#[test]
fn test_product() {
/*
$ python -c 'import itertools; print(list(itertools.product([0,1,2,3],[100,200])))'
[(0, 100), (0, 200), (1, 100), (1, 200), (2, 100), (2, 200), (3, 100), (3, 200)]
*/
    let f = || vec![0,1,2,3].into_par_iter();
    let g = || vec![100,200].into_par_iter();
    let out1 = parallel_cartesian_product!(f,g).collect::<Vec<(u8, u8)>>();
    assert_eq!(out1, vec![(0, 100), (0, 200), (1, 100), (1, 200), (2, 100), (2, 200), (3, 100), (3, 200)]);
    println!("{:?}", out1);

    let genh = || || b"\x00\x01".into_par_iter().cloned();
    let (h1, h2, h3) = (genh(), genh(), genh());
    let out2 = parallel_cartesian_product!(h1, h2, h3).collect::<Vec<((u8, u8), u8)>>();
    let out2 = out2.into_iter().map(|((x, y),z)| vec![x,y,z]).collect::<Vec<Vec<u8>>>();
    assert_eq!(out2, vec![[0, 0, 0], [0, 0, 1], [0, 1, 0], [0, 1, 1], [1, 0, 0], [1, 0, 1], [1, 1, 0], [1, 1, 1]]);
    println!("{:?}", out2);
}

enum InputType {
    Alphanumeric,
    Printable,
    U64,
}

struct InputOptions {
    mask: Vec<u8>,
    goal: Vec<u8>,
    inputsuffix: Option<Vec<u8>>,
    inputtype: InputType,
}

fn proofofwork<F>(i: InputOptions, done: Arc<atomic::AtomicBool>, f: F) -> futures::sync::oneshot::Receiver<Option<(String, String)>> where
    F: Fn(&[u8]) -> [u8; 32] + Send + Sync + 'static {
    assert_eq!(i.mask.len(), i.goal.len());
    assert_eq!(i.mask.len(), 32);
    let mut shift = [0; 8];
    let _ = ring::rand::SystemRandom::new().fill(&mut shift[..]);
    let shift = LittleEndian::read_u64(&shift);
    let (send, recv) = futures::sync::oneshot::channel();
    rayon::spawn_async(move || {
        let mask = i.mask; let mask = &mask[..];
        let goal = i.goal; let goal = &goal[..];
        let inputsuffix = i.inputsuffix;
        let attempt_hash = |mut x: Vec<u8>| {
            if let Some(ref suffix) = inputsuffix {
                x.extend_from_slice(suffix);
            }
            // TODO: efficient alphanumeric hashes
            //if !tmpinput.iter().all(|&c| (c as char).is_alphanumeric()) { return None; }
            let tmpoutput = f(&x);
            if mask.iter().zip(goal).zip(tmpoutput.iter()).all(|((m, g), o)| (m & o) == (m & g)) {
                //return Some((std::str::from_utf8(&x).unwrap().into(), hasher.result_str()));
                return Some((x.to_hex(), f(&x).to_hex()));
            }
            None
        };
        let u64space = (0..(0u64.wrapping_sub(1))).into_par_iter() // Brute force over a 64-bit input space
            .map(|x| x.wrapping_add(shift)) // Randomize the starting space
            .map(|x| { let mut tmpinput = vec![0; 8]; LittleEndian::write_u64(&mut tmpinput[0..8], x); tmpinput });

        let printable5space = {
            // TODO: randomization
            let f = || || (b' '..b'~'+1).into_par_iter(); // printable chars
            let (a,b,c,d,e) = (f(), f(), f(), f(), f());
            parallel_cartesian_product!(a,b,c,d,e).map(|((((a,b),c),d),e)| vec![a,b,c,d,e])
        };
        let alphanumeric5space = {
            // TODO: randomization
            let f = || || (b'0'..b'Z'+1).into_par_iter().chain((b'a'..b'z'+1).into_par_iter()); // alphanumeric chars
            let (a,b,c,d,e) = (f(), f(), f(), f(), f());
            parallel_cartesian_product!(a,b,c,d,e).map(|((((a,b),c),d),e)| vec![a,b,c,d,e])
        };
        // duplication because ParallelIterators can't be traitobjected
        // TODO: generic continuation function?
        match i.inputtype {
            InputType::Alphanumeric => {
                let result = alphanumeric5space
                    .map(attempt_hash) // calculate the hashes
                    .find_any(|x| (x.is_some() || done.load(atomic::Ordering::Relaxed))) // abort early if we're done (i.e. client cancelled)
                    .and_then(|x| x); // ignore the difference between finding no matching hashes and aborting early (`bind id` == `join`)
                done.store(true, atomic::Ordering::Relaxed);
                let _ = send.send(result);
            },
            InputType::Printable => {
                let result = printable5space
                    .map(attempt_hash) // calculate the hashes
                    .find_any(|x| (x.is_some() || done.load(atomic::Ordering::Relaxed))) // abort early if we're done (i.e. client cancelled)
                    .and_then(|x| x); // ignore the difference between finding no matching hashes and aborting early (`bind id` == `join`)
                done.store(true, atomic::Ordering::Relaxed);
                let _ = send.send(result);
            },
            InputType::U64 => {
                let result = u64space
                    .map(attempt_hash) // calculate the hashes
                    .find_any(|x| (x.is_some() || done.load(atomic::Ordering::Relaxed))) // abort early if we're done (i.e. client cancelled)
                    .and_then(|x| x); // ignore the difference between finding no matching hashes and aborting early (`bind id` == `join`)
                done.store(true, atomic::Ordering::Relaxed);
                let _ = send.send(result);
            },
        }
    });
    recv
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

struct POWService(Arc<atomic::AtomicBool>, Handle);
impl Service for POWService {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=hyper::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        match *req.method() {
            hyper::Get => (),
            _ => return Box::new(future::ok(Response::new().with_status(StatusCode::NotFound))),
        }
        match req.path() {
            "/sha256" => { powserver(&req, self.0.clone(), &self.1, ring_sha256) }
            "/md5" => { powserver(&req, self.0.clone(), &self.1, openssl_sys_md5) }
            _ => Box::new(future::ok(Response::new().with_body(HELP_MSG.as_bytes())))
        }
    }
}

fn to_hyper_error<E: std::error::Error+Send+Sync+'static>(e: E) -> hyper::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e).into()
}

/*enum Interleave<F, S> {
    Nil,
    Step(F, S),
    StreamExhausted(F),
}
impl<F,S,T,E> Future for Interleave<F, S> where
    T: std::fmt::Debug, E: std::fmt::Debug,
    F: Future<Item=T, Error=E>,
    S: Stream<Item=(), Error=E> {
    type Item = T;
    type Error = E;
    fn poll(&mut self) -> futures::Poll<T, E> {
        use futures::Async::*;
        use Interleave::*;
        let state = std::mem::replace(self, Nil);
        println!("Interleave::poll({})", match state {
            Nil => "Nil",
            Step(_, _) => "Step",
            StreamExhausted(_) => "StreamExhausted",
        });
        let tmp = match state {
            Nil => panic!("Attempted to poll interleave while Nil"),
            Step(mut f, mut s) => match (f.poll(), s.poll()) {
                (Ok(Ready(t)), _) => Ok(Ready(t)),
                (_, Ok(Ready(None))) => { *self = StreamExhausted(f); Ok(NotReady) },
                (_, Ok(Ready(Some(())))) => { *self = Step(f, s); Ok(NotReady) },
                (Ok(NotReady), Ok(NotReady)) => { *self = Step(f, s); Ok(NotReady) },
                (Err(e), _) => Err(e),
                (_, Err(e)) => Err(e),
            },
            StreamExhausted(mut f) => match f.poll() {
                Ok(Ready(t)) => Ok(Ready(t)),
                Ok(NotReady) => { *self = StreamExhausted(f); Ok(NotReady) },
                Err(e) => Err(e),
            },
        };
        println!("returning {:?}", tmp);
        tmp
    }
}*/

fn powserver<F>(req: &Request, done: Arc<atomic::AtomicBool>, handle: &Handle, f: F) -> Box<Future<Item=Response, Error=hyper::Error>> where
    F: Fn(&[u8]) -> [u8; 32] + Send + Sync + 'static {
    let base_url = Url::parse("http://foo").unwrap();
    println!("{:?}", req.uri());
    println!("{:?}", req.headers());
    if let Ok(url) = Url::options().base_url(Some(&base_url)).parse(req.uri().as_ref()) {
        let mut mask = None;
        let mut goal = None;
        let mut inputsuffix = None;
        let mut inputtype = InputType::U64;
        for (k, v) in url.query_pairs() {
            if k == "mask" && v.len() == 32*2 {
                mask = v.from_hex().ok();
            }
            if k == "goal" && v.len() == 32*2 {
                goal = v.from_hex().ok();
            }
            if k == "inputsuffix" {
                inputsuffix = v.from_hex().ok();
            }
            if k == "printable" {
                inputtype = InputType::Printable;
            }
            if k == "alphanumeric" {
                inputtype = InputType::Alphanumeric;
            }
        }
        println!("mask: {:?}\ngoal: {:?}", mask.clone().map(|x| x.to_hex()), goal.clone().map(|x| x.to_hex()));
        if let (Some(mask), Some(goal)) = (mask, goal) {
            let (send, recv) = futures::sync::mpsc::channel(10);
            let body: hyper::Body = recv.into();
            let resp = Response::new().with_body(body);
            let timer = match Timeout::new(Duration::from_secs(1), handle).map_err(to_hyper_error) {
                Ok(timer) => timer,
                Err(e) => return Box::new(future::err(to_hyper_error(e))),
            };
            let progressindicator = {
                let done = done.clone();
                stream::unfold((send.clone(), timer, handle.clone()), move |(send, timer, handle)| {
                    if done.load(atomic::Ordering::Relaxed) {
                        println!("progressindicator: done");
                        return None;
                    }
                    let nextiter = timer.map_err(to_hyper_error).and_then(|()| {
                        let sent = send.send(Ok("x".into())).map_err(to_hyper_error);
                        let flushed = sent.and_then(|send| { send.flush().map_err(to_hyper_error) });
                        flushed.and_then(|send| {
                            let timer = Timeout::new(Duration::from_secs(1), &handle).map_err(to_hyper_error)?;
                            Ok(((), (send, timer, handle)))
                        })
                    });
                    Some(nextiter)
                })
            };
            let beginning = send.send(Ok("{\"progressbar\":\"".into()).into()).map_err(to_hyper_error);
            let inputoptions = InputOptions {
                mask: mask, goal: goal,
                inputsuffix: inputsuffix,
                inputtype: inputtype,
            };
            let pow = proofofwork(inputoptions, done.clone(), f).map_err(to_hyper_error);
            let pow = beginning.join(pow).and_then(move |(send, opt)| {
                if let Some((x, hash)) = opt {
                    println!("sending preimage {}", x);
                    send.send(Ok(format!("\", \"preimage_hex\":\"{}\", \"image_hex\":\"{}\"}}", x, hash).into()))
                } else {
                    send.send(Ok("\", \"error\":\"Cancelled or exhausted search space\"}".into()))
                }.map(|_| ()).map_err(to_hyper_error)
            });
            handle.spawn(pow.select(progressindicator.for_each(|()| Ok(()))).map(|_| ()).map_err(|_| ()));
            return Box::new(future::ok(resp));
        }
    }
    Box::new(future::ok(Response::new().with_body(HELP_MSG.as_bytes())))
}

fn main() {
    if let Some(Ok(port)) = std::env::args().nth(1).map(|x| x.parse::<u16>()) {
        println!("current_num_threads: {}", rayon::current_num_threads());
        println!("openssl version info: {:?}", openssl::version::c_flags());
        let bindaddr = ("0.0.0.0".parse::<std::net::IpAddr>().unwrap(), port);
        /*Http::new().bind(&bindaddr.into(), || Ok(POWService)).expect("Failed to bind server")
            .run().expect("Fatal error while running the server");*/
        let mut core = Core::new().unwrap();
        let handle = core.handle();
        let listener = TcpListener::bind(&bindaddr.into(), &handle).unwrap();
        core.run(listener.incoming().for_each(|(sock, addr)| {
            let http = Http::new();
            let (sock, hup) = detect_hup(sock);
            let done = Arc::new(atomic::AtomicBool::new(false));
            //let http = InjectZeroLengthReads(http, Duration::from_secs(1));
            http.bind_connection(&handle, sock, addr, POWService(done.clone(), handle.clone()));
            handle.spawn(hup.and_then(move |()| {
                println!("detected HUP");
                done.store(true, atomic::Ordering::Relaxed);
                Ok(())
            }).map_err(|_| ()));
            Ok(())
        })).unwrap();
    } else {
        println!("Expecting the port as the first argument.");
    }
}

#[test]
fn test_pow() {
    println!("current_num_threads: {}", rayon::current_num_threads());
    println!("POW: {:?}", proofofwork(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff".to_vec(),
                                      b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\x85\xbd".to_vec(),
                                      None,
                                      Arc::new(atomic::AtomicBool::new(false)),
                                      ring_sha256).wait());
}
