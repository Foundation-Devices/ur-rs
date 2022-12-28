use honggfuzz::fuzz;
use ur::UR;

fn main() {
    loop {
        fuzz!(|ur: &str| {
            UR::parse(ur).ok();
        });
    }
}
