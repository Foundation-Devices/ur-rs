use honggfuzz::fuzz;
use std::collections::BTreeSet;
use std::sync::Mutex;
use ur::fountain::{
    chooser::{FragmentChooser, HeaplessFragmentChooser},
    part::Part,
};

const MAX_SEQUENCE_COUNT: usize = 65_536;

static STATIC_CHOOSER: Mutex<HeaplessFragmentChooser<MAX_SEQUENCE_COUNT>> =
    Mutex::new(HeaplessFragmentChooser::new_heapless());

fn main() {
    loop {
        fuzz!(|part: Part| {
            if !part.is_valid() || part.sequence_count > MAX_SEQUENCE_COUNT.try_into().unwrap() {
                return;
            }

            let mut heapless_chooser = STATIC_CHOOSER.lock().unwrap();
            let mut chooser = FragmentChooser::default();

            let indexes: BTreeSet<usize> = heapless_chooser.choose_fragments(
                part.sequence,
                part.sequence_count,
                part.checksum,
            );
            assert!(!indexes.is_empty());

            let indexes: BTreeSet<usize> =
                chooser.choose_fragments(part.sequence, part.sequence_count, part.checksum);
            assert!(!indexes.is_empty());
        });
    }
}
