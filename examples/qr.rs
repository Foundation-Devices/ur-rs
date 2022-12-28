use qrcode::QrCode;
use ur::HeaplessEncoder;

use std::io::Write;
use std::sync::Mutex;

static ENCODER: Mutex<HeaplessEncoder<5, 128>> = Mutex::new(HeaplessEncoder::new_heapless());

fn main() {
    let message = std::env::args().last().unwrap().into_bytes().leak();

    let mut encoder = ENCODER.lock().unwrap();
    encoder.start("bytes", message, 5);
    let mut stdout = std::io::stdout();
    loop {
        let ur = encoder.next_part();
        let code = QrCode::new(&ur.to_string()).unwrap();
        let string = code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        stdout.write_all(format!("{string}\n").as_bytes()).unwrap();
        stdout
            .write_all(format!("{ur}\n\n\n\n").as_bytes())
            .unwrap();
        stdout.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
