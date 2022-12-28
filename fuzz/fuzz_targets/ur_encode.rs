use arbitrary::Arbitrary;
use honggfuzz::fuzz;
use std::num::NonZeroUsize;
use ur::fountain::fragment_length;
use ur::Encoder;

const MAX_FRAGMENT_LENGTH: usize = 100;
const MAX_SEQUENCE_COUNT: usize = 1_024;

pub type HeaplessEncoder<'a, 'b> =
    ur::HeaplessEncoder<'a, 'b, MAX_FRAGMENT_LENGTH, MAX_SEQUENCE_COUNT>;

fn main() {
    loop {
        #[derive(Arbitrary)]
        struct FuzzInput<'a> {
            data: &'a [u8],
            max_fragment_length: NonZeroUsize,
            iterations: usize,
        }

        fuzz!(|input: FuzzInput| {
            if input.data.is_empty() {
                return;
            }

            let nominal_length = fragment_length(input.data.len(), input.max_fragment_length.get());
            if nominal_length > MAX_FRAGMENT_LENGTH {
                return;
            }

            let mut heapless_encoder = HeaplessEncoder::new_heapless();
            let mut encoder = Encoder::new();

            heapless_encoder.start("bytes", input.data, input.max_fragment_length.into());
            encoder.start("bytes", input.data, input.max_fragment_length.into());

            for _ in 0..input.iterations {
                let part = heapless_encoder.next_part();
                part.to_string();

                let part = encoder.next_part();
                part.to_string();
            }
        });
    }
}
