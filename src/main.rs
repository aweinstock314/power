extern crate byteorder;
extern crate crypto;
extern crate hyper;
extern crate rayon;
extern crate rustc_serialize;
extern crate url;

use byteorder::{ByteOrder, LittleEndian};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri;
use rayon::current_num_threads;
use rayon::prelude::*;
use rustc_serialize::hex::{FromHex, ToHex};
use std::io::Write;
use url::Url;

fn proofofwork(mask: &[u8], goal: &[u8]) -> (String, String) {
    assert_eq!(mask.len(), goal.len());
    assert_eq!(mask.len(), 32);
    let f = |x: u64| {
        let mut tmpinput = [0; 8];
        let mut tmpoutput = [0; 32];
        LittleEndian::write_u64(&mut tmpinput, x);
        // TODO: efficient alphanumeric hashes
        //if !tmpinput.iter().all(|&c| (c as char).is_alphanumeric()) { return None; }
        let mut hasher = Sha256::new();
        hasher.input(&tmpinput);
        hasher.result(&mut tmpoutput);
        if mask.iter().zip(goal).zip(tmpoutput.iter()).all(|((&m, &g), o)| (m & o) == (m & g)) {
            //return Some((std::str::from_utf8(&tmpinput).unwrap().into(), hasher.result_str()));
            return Some((tmpinput.to_hex(), hasher.result_str()));
        }
        None
    };
    (0..2u64.pow(63)).into_par_iter().filter_map(|x| f(x)).find_any(|_| true).unwrap()
}

fn powserver(req: Request, resp: Response) {
    let base_url = Url::parse("http://foo").unwrap();
    println!("{:?}", req.uri);
    println!("{:?}", req.headers);
    if let RequestUri::AbsolutePath(path) = req.uri {
        if let Ok(url) = Url::options().base_url(Some(&base_url)).parse(&path) {
            if url.path() == "/sha256" {
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
                println!("{:?} {:?}", mask, goal);
                if let (Some(mask), Some(goal)) = (mask, goal) {
                    let mut resp = resp.start().unwrap();
                    let (x, hash) = proofofwork(&mask, &goal);
                    println!("sending preimage {}", x);
                    writeln!(resp, "{} has hash {}", x, hash).unwrap();
                    resp.end().unwrap();
                    return;
                }
            }
        }
    }
    resp.send("Usage examples:
$ time curl localhost:3000/sha256?mask=$(python -c 'print \"00\"*29+\"ff\"*3')\\&goal=$(python -c 'print \"00\"*29+\"deadbe\"')
159a360000000000 has hash 9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe

real    0m3.049s
user    0m0.040s
sys     0m0.008s
$ python -c 'import sys; sys.stdout.write(\"159a360000000000\".decode(\"hex\"))' | sha256sum
9d0ec7b3dd909e1d7ee64186e13b8065c32e88695c8aa938bdbb9a9c6ddeadbe  -
$ time curl localhost:3000/sha256?mask=$(python -c 'print \"0fff\"+\"00\"*28+\"ff\"*2')\\&goal=$(python -c 'print \"dead\"+\"00\"*28+\"beef\"')
ee00ad0000000060 has hash 2eadd4a8cf0ea220da5570e0ac7855ffc6e416e09c08e0a7b81fbac0fcaabeef

real    0m9.760s
user    0m0.020s
sys     0m0.012s
$ python
>>> import requests
>>> requests.get('http://localhost:3000/sha256', params={'mask': '00'+'ff'*3+'00'*28, 'goal': '00badc0d'+'00'*28}).text
u'78a3170000000000 has hash fcbadc0d5856bb6eea467a236218eb5e16017a1636e335e2946618feb0aae620\\n'
>>> requests.get('http://localhost:3000/sha256', params={'mask': 'ff'*4+'00'*28, 'goal': '00abcdef'+'00'*28}).text
u'c72b530200000040 has hash 00abcdef83801fd557e1740187560ac4fdc557645e175f5faeb407e54a2d9958\\n'

Intended general usage (more algos will be added later):
GET /sha256?mask=<some 32 byte hex encoded mask>&goal=<some 32 byte hex encoded goal>
".as_bytes()).unwrap();
}

fn main() {
    if let Some(Ok(port)) = std::env::args().nth(1).map(|x| x.parse::<u16>()) {
        println!("current_num_threads: {}", current_num_threads());
        Server::http(("0.0.0.0", port)).expect("Failed to initialize server")
            .handle(powserver).expect("Failed to initialize handler");
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
