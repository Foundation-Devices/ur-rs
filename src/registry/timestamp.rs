//! CBOR timestamp.

use minicbor::data::{Int, Tag, Type};
use minicbor::encode::{Error, Write};
use minicbor::{Decode, Decoder, Encode, Encoder};

/// Timestamp.
#[derive(Debug)]
pub enum Timestamp {
    /// Integer timestamp.
    Int(Int),
    /// Floating point timestamp.
    Float(f64),
}

#[rustfmt::skip]
impl<'b, C> Decode<'b, C> for Timestamp {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        if d.tag()? != Tag::Timestamp {
            return Err(minicbor::decode::Error::message("invalid timestamp tag"));
        }

        #[rustfmt::skip]
        let timestamp = match d.datatype()? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 |
            Type::I8 | Type::I16 | Type::I32 | Type::I64 |
            Type::Int => Timestamp::Int(d.int()?),
            Type::F16 | Type::F32 | Type::F64 => Timestamp::Float(d.f64()?),
            _ => return Err(minicbor::decode::Error::message("invalid timestamp")),
        };

        Ok(timestamp)
    }
}

impl<C> Encode<C> for Timestamp {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _ctx: &mut C) -> Result<(), Error<W::Error>> {
        e.tag(Tag::Timestamp)?;

        match self {
            Timestamp::Int(x) => e.int(*x)?,
            Timestamp::Float(x) => e.f64(*x)?,
        };

        Ok(())
    }
}
