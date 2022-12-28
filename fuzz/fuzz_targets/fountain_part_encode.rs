use honggfuzz::fuzz;
use ur::fountain::part::Part;

fn main() {
    loop {
        fuzz!(|part: Part| {
            let mut buf = [0; 1024];
            minicbor::encode(part, &mut buf[..]).ok();
        })
    }
}
