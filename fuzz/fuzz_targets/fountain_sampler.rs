use honggfuzz::fuzz;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use ur::fountain::sampler::{HeaplessWeighted, Weighted};

const MAX_COUNT: usize = 500_000;
static STATIC_WEIGHTED: Mutex<HeaplessWeighted<MAX_COUNT>> =
    Mutex::new(HeaplessWeighted::new_heapless());

fn main() {
    loop {
        fuzz!(|count: NonZeroUsize| {
            if count.get() as u64 >= u32::MAX as u64 {
                return;
            }

            let mut weighted = Weighted::default();
            weighted.set((0..count.get()).map(|i| 1.0 / (i + 1) as f64));

            if count.get() > MAX_COUNT {
                return;
            }
            let mut weighted = STATIC_WEIGHTED.lock().unwrap();
            weighted.set((0..count.get()).map(|i| 1.0 / (i + 1) as f64));
        })
    }
}
