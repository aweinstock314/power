#![feature(test)]
extern crate futures;
extern crate rayon;
extern crate tokio_core;
extern crate test;

use futures::{Future, Stream, Sink};
use rayon::iter::ParallelIterator;
use rayon::iter::IntoParallelIterator;

fn expensive_work() -> u64 {
    (0..(0u64).wrapping_sub(1)).into_par_iter().reduce(|| 0u64, |x, y|
        // without black_box, LLVM optimizes away the parallel iterator and returns 9223372036854775809
        test::black_box(x.wrapping_add(y)))
}

fn buggy() {
    let slow = rayon::spawn_future_async(futures::future::lazy(move || { Ok(expensive_work()) })).map_err(|()| /* type inference hack */ ());
    let fast = futures::future::ok(42);
    let mut core = tokio_core::reactor::Core::new().unwrap();
    println!("{:?}", core.run(slow.select(fast).map(|(res, _selectnext)| res).map_err(|(err, _selectnext)| err)).unwrap());
    // Expected: 100% chance of instant "42", barring pathological custom schedulers
    // Actual: 50% chance of instant "42", 50% chance of 100% CPU usage across all cores doing number crunching
}

fn working() {
    let (send, recv) = futures::sync::mpsc::channel(10);
    let slow = rayon::spawn_future_async(futures::future::lazy(move || { Ok(expensive_work()) }).and_then(|res| send.send(res)));
    let fast = futures::future::ok(42);
    rayon::spawn_async(move || { let _ = slow.rayon_wait(); }); // this feels kind of hacky/redundant
    let mut core = tokio_core::reactor::Core::new().unwrap();
    println!("{:?}", core.run(recv.into_future().map(|(a, _)| a.unwrap()).select(fast).map(|(res, _selectnext)| res).map_err(|(err, _selectnext)| err)).unwrap());
}

fn working_simplified() {
    let (send, recv) = futures::sync::oneshot::channel();
    rayon::spawn_async(move || {
        let _ = send.send(expensive_work());
    });
    let fast = futures::future::ok(42);
    let mut core = tokio_core::reactor::Core::new().unwrap();
    println!("{:?}", core.run(recv.select(fast).map(|(res, _selectnext)| res).map_err(|(err, _selectnext)| err)).unwrap());
}

fn main() {
    // strangely, "buggy" seems to work correctly if "working" is run first, but has the 50% behavior if "working" is commented out, or if the order is swapped. maybe it's an initialization thing?
    rayon::initialize(rayon::Configuration::new()).unwrap(); // this doesn't seem to help though
    //working_simplified();
    println!("-----");
    buggy();
}
