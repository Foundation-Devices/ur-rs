use honggfuzz::fuzz;
use ur::fountain::part::Part;

fn main() {
    loop {
        fuzz!(|buf: &[u8]| {
            minicbor::decode::<Part>(&buf[..]).ok();
        })
    }
}
