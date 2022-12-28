use arbitrary::Arbitrary;
use honggfuzz::fuzz;
use ur::bytewords::Style;

fn main() {
    #[derive(Arbitrary)]
    struct FuzzInput<'a> {
        data: &'a [u8],
        style: Style,
    }

    loop {
        fuzz!(|input: FuzzInput| {
            let encoded = ur::bytewords::encode(input.data, input.style);
            let decoded = ur::bytewords::decode(&encoded, input.style).unwrap();
            assert_eq!(input.data, decoded);
        });
    }
}
