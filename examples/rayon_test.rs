#![feature(test)]
extern crate futures;
extern crate rayon;
extern crate tokio_core;
extern crate test;

use futures::{Future, Stream, Sink};
use rayon::iter::ParallelIterator;
use rayon::iter::IntoParallelIterator;

fn buggy() {
    let noprogress = rayon::spawn_future_async(futures::future::lazy(move || {
     Ok((0..(0u64).wrapping_sub(1)).into_par_iter().reduce(|| 0u64, |x, y|
         // without black_box, LLVM optimizes away the parallel iterator and returns 9223372036854775809
         test::black_box(x.wrapping_add(y))))
    })).map_err(|()| /* type inference hack */ ());
    let progress = futures::future::ok(42);
    let mut core = tokio_core::reactor::Core::new().unwrap();
    println!("{:?}", core.run(noprogress.select(progress).map(|(res, _selectnext)| res).map_err(|(err, _selectnext)| err)).unwrap());
    // Expected: 100% chance of instant "42", barring pathological custom schedulers
    // Actual: 50% chance of instant "42", 50% chance of 100% CPU usage across all cores doing number crunching
}

fn working() {
    let (send, recv) = futures::sync::mpsc::channel(10);
    let noprogress = rayon::spawn_future_async(futures::future::lazy(move || {
        Ok((0..(0u64).wrapping_sub(1)).into_par_iter().reduce(|| 0u64, |x, y|
            // without black_box, LLVM optimizes away the parallel iterator and returns 9223372036854775809
            test::black_box(x.wrapping_add(y))))
    }).and_then(|res| send.send(res)));
    let progress = futures::future::ok(42);
    rayon::spawn_async(move || { let _ = noprogress.rayon_wait(); }); // this feels kind of hacky_redundant
    let mut core = tokio_core::reactor::Core::new().unwrap();
    println!("{:?}", core.run(recv.into_future().map(|(a, _)| a.unwrap()).select(progress).map(|(res, _selectnext)| res).map_err(|(err, _selectnext)| err)).unwrap());
}

fn main() {
    // strangely, "buggy" seems to work correctly if "working" is run first, but has the 50% behavior if "working" is commented out, or if the order is swapped. maybe it's an initialization thing?
    working();
    println!("-----");
    buggy();
}
