//! CBOR encoding and decoding of [`Uuid`] types.

use minicbor::data::Tag;
use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};
use uuid::Uuid;

/// Tag representing an [`Uuid`].
pub const TAG: Tag = Tag::Unassigned(37);

/// Encode an [`Uuid`].
pub fn encode<C, W: Write>(
    uuid: &Uuid,
    e: &mut Encoder<W>,
    _ctx: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.tag(TAG)?.bytes(uuid.as_bytes())?;
    Ok(())
}

/// Decode an [`Uuid`].
pub fn decode<C>(d: &mut Decoder, _ctx: &mut C) -> Result<Uuid, minicbor::decode::Error> {
    if d.tag()? != TAG {
        todo!()
    };

    let uuid = d.bytes()?;
    if uuid.len() != 16 {
        todo!()
    }

    let mut buf = [0u8; 16];
    buf.copy_from_slice(uuid);
    Ok(Uuid::from_bytes(buf))
}
