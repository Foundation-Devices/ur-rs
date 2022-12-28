//! Elliptic-Curve key.

use core::{fmt, fmt::Debug};

use minicbor::data::Type;
use minicbor::decode::Error;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

/// Elliptic-Curve key.
#[doc(alias("crypto-eckey"))]
pub struct ECKey<'a> {
    /// The type of the key curve.
    pub curve: u64,
    /// True if the key is a private key.
    pub is_private: bool,
    /// The key material.
    pub data: &'a [u8],
}

impl<'a> Debug for ECKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ECKey");

        debug
            .field("curve", &self.curve)
            .field("is_private", &self.is_private);

        if self.is_private {
            debug.field("data", &"[PrivateKey]");
        } else {
            debug.field("data", &self.data);
        }

        debug.finish()
    }
}

impl<'b, C> Decode<'b, C> for ECKey<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let mut curve = 0;
        let mut is_private = false;
        let mut data = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => curve = d.u64()?,
                    2 => is_private = d.bool()?,
                    3 => data = Some(d.bytes()?),
                    _ => return Err(Error::message("unknown map entry")),
                }
            };
        }

        if let Some(len) = d.map()? {
            for _ in 0..len {
                decode_inner!();
            }
        } else {
            while d.datatype()? != Type::Break {
                decode_inner!();
            }
        }

        Ok(Self {
            curve,
            is_private,
            data: data.ok_or_else(|| Error::message("data is missing"))?,
        })
    }
}

impl<'a, C> Encode<C> for ECKey<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let curve_is_not_default = self.curve != 0;
        let is_private_is_not_default = self.is_private != false;

        let len = curve_is_not_default as u64 + is_private_is_not_default as u64 + 1;
        e.map(len)?;

        if curve_is_not_default {
            e.u8(1)?.u64(self.curve)?;
        }

        if is_private_is_not_default {
            e.u8(2)?.bool(self.is_private)?;
        }

        e.u8(3)?.bytes(self.data)?;

        Ok(())
    }
}
