use honggfuzz::fuzz;
use std::sync::Mutex;
use ur::{Decoder, HeaplessDecoder, UR};

const MAX_MESSAGE_LEN: usize = 1_000;
const MAX_MIXED_PARTS: usize = 100;
const MAX_FRAGMENT_LEN: usize = 100;
const MAX_SEQUENCE_COUNT: usize = 1_024;
const MAX_QUEUE_SIZE: usize = 64;

static STATIC_DECODER: Mutex<
    HeaplessDecoder<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        MAX_QUEUE_SIZE,
    >,
> = Mutex::new(HeaplessDecoder::new_heapless());

fn main() {
    loop {
        fuzz!(|elements: Vec<UR>| {
            let mut heapless_decoder = STATIC_DECODER.lock().unwrap();
            let mut decoder = Decoder::default();

            for ur in elements {
                heapless_decoder.receive(&ur).ok();
                decoder.receive(&ur).ok();
            }
        });
    }
}
