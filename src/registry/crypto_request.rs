//! Request to Airgapped Device.

use core::marker::PhantomData;

use crate::registry::crypto_seed;
use minicbor::data::Type;
use minicbor::{data::Tag, decode::Error, encode::Write, Decode, Decoder, Encode, Encoder};
use uuid::Uuid;

/// Default `crypto-request` type that supports only standard requests.
#[doc(alias("crypto-request"))]
pub type CryptoRequest<'a> = BaseCryptoRequest<'a, Empty>;

/// Base `crypto-request` type.
///
/// Allows specifying `Other` type which may be used to decode request bodies
/// that are not known or supported by this crate.
#[doc(alias("crypto-request"))]
#[derive(Debug)]
pub struct BaseCryptoRequest<'a, Other> {
    /// Transaction identification.
    pub transaction_id: Uuid,
    /// Request body.
    pub body: Body<Other>,
    /// Optional description.
    pub description: Option<&'a str>,
}

impl<'b, C, Other> Decode<'b, C> for BaseCryptoRequest<'b, Other>
where
    Other: Decode<'b, C>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        use crate::registry::uuid;

        let mut transaction_id = None;
        let mut body = None;
        let mut description = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 if transaction_id.is_none() => transaction_id = Some(uuid::decode(d, ctx)?),
                    2 if body.is_none() => body = Some(Body::decode(d, ctx)?),
                    3 if description.is_none() => description = Some(d.str()?),
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
            d.skip()?;
        }

        Ok(Self {
            transaction_id: transaction_id
                .ok_or_else(|| Error::message("transaction-id is not present"))?,
            body: body.ok_or_else(|| Error::message("request-boyd is not present"))?,
            description,
        })
    }
}

impl<'a, C, Other> Encode<C> for BaseCryptoRequest<'a, Other>
where
    Other: Encode<C>,
{
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        use crate::registry::uuid;

        e.map(if self.description.is_some() { 3 } else { 2 })?;

        e.u8(1)?;
        uuid::encode(&self.transaction_id, e, ctx)?;

        e.u8(2)?;
        self.body.encode(e, ctx)?;

        if let Some(description) = self.description {
            e.u8(3)?.str(description)?;
        }

        Ok(())
    }
}

/// The body of a [`crypto-request`](BaseCryptoRequest).
#[doc(alias("request-body"))]
#[derive(Debug)]
pub enum Body<Other> {
    /// Request a seed from a digest.
    RequestSeed(RequestSeed),
    /// Other type(s) of crypto-request bodies that do not
    Other(Other),
}

impl<'b, C, Other> Decode<'b, C> for Body<Other>
where
    Other: Decode<'b, C>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let body = match d.probe().tag()? {
            RequestSeed::TAG => Body::RequestSeed(RequestSeed::decode(d, ctx)?),
            Tag::Unassigned(_) => Body::Other(Other::decode(d, ctx)?),
            _ => return Err(Error::message("invalid request-body tag")),
        };

        Ok(body)
    }
}

impl<Other, C> Encode<C> for Body<Other>
where
    Other: Encode<C>,
{
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Body::RequestSeed(seed) => seed.encode(e, ctx)?,
            Body::Other(other) => other.encode(e, ctx)?,
        }

        Ok(())
    }
}

/// Empty type for [`Body::Other`] that fails to decode and cannot be
/// constructed.
#[derive(Debug)]
pub struct Empty(PhantomData<()>);

impl<'b, C> Decode<'b, C> for Empty {
    fn decode(_: &mut Decoder<'b>, _: &mut C) -> Result<Self, Error> {
        Err(Error::message("unknown crypto-request body tag type"))
    }
}

impl<C> Encode<C> for Empty {
    fn encode<W: Write>(
        &self,
        _: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        unreachable!()
    }
}

/// Request seed matching the requested fingerprint.
#[derive(Debug)]
#[doc(alias = "request-seed")]
pub struct RequestSeed {
    /// The SHA-256 hash of the seed.
    pub seed_digest: [u8; 32],
}

impl RequestSeed {
    /// Tag representing a [`RequestSeed`].
    pub const TAG: Tag = Tag::Unassigned(500);
}

impl<'b, C> Decode<'b, C> for RequestSeed {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        if RequestSeed::TAG != d.tag()? {
            return Err(Error::message("invalid tag for request-seed"));
        }

        let mut seed_digest = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 if seed_digest.is_none() => {
                        seed_digest = Some(crypto_seed::digest::decode(d, ctx)?)
                    }
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
            d.skip()?;
        }

        Ok(Self {
            seed_digest: seed_digest.ok_or_else(|| Error::message("seed-digest is not present"))?,
        })
    }
}

impl<C> Encode<C> for RequestSeed {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.tag(Self::TAG)?;

        e.map(1)?;
        e.u8(1)?;
        crypto_seed::digest::encode(&self.seed_digest, e, ctx)?;

        Ok(())
    }
}
