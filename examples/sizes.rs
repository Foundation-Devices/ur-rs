const QR13L_MAX: usize = 425;

fn print_static_encoder_size<const FRAGMENT_MAX: usize, const SEQ_MAX: usize>() {
    println!(
        "Static Encoder: {} bytes.",
        std::mem::size_of::<ur::HeaplessEncoder<'_, '_, FRAGMENT_MAX, SEQ_MAX>>(),
    );
}

fn print_static_decoder_size<
    const MAX_MESSAGE_LEN: usize,
    const MAX_MIXED_PARTS: usize,
    const MAX_FRAGMENT_LEN: usize,
    const MAX_SEQUENCE_COUNT: usize,
    const QUEUE_SIZE: usize,
    const MAX_UR_TYPE: usize,
>() {
    println!(
        "Static Decoder: {} bytes.",
        std::mem::size_of::<
            ur::HeaplessDecoder<
                MAX_MESSAGE_LEN,
                MAX_MIXED_PARTS,
                MAX_FRAGMENT_LEN,
                MAX_SEQUENCE_COUNT,
                QUEUE_SIZE,
                MAX_UR_TYPE,
            >,
        >(),
    );
}

fn main() {
    println!(
        "Dynamic Decoder: {} bytes.",
        std::mem::size_of::<ur::Decoder>()
    );
    println!(
        "Dynamic Encoder: {} bytes.",
        std::mem::size_of::<ur::Encoder<'_, '_>>()
    );
    print_static_decoder_size::<4096, 16, QR13L_MAX, 30, 16, { "crypto-coin-info".len() }>();
    print_static_encoder_size::<QR13L_MAX, 100>();
}
