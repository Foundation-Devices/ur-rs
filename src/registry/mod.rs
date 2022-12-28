//! Registry.

use crate::collections::Vec;
use core::fmt;
use core::fmt::Formatter;
use minicbor::bytes::ByteSlice;
use minicbor::{Decode, Encode, Encoder};

pub mod crypto_address;
pub mod crypto_eckey;
pub mod crypto_hdkey;
//pub mod crypto_output;
pub mod crypto_request;
pub mod crypto_seed;
pub mod timestamp;
pub mod uuid;

/// Default type for UR values containing only known ones.
#[cfg(feature = "alloc")]
pub type Value<'a> =
    BaseValue<'a, crypto_request::Empty, alloc::vec::Vec<crypto_hdkey::PathComponent>>;

/// A type that known UR values.
#[derive(Debug)]
pub enum BaseValue<'a, Other, C> {
    /// Undifferentiated byte string.
    #[doc(alias("bytes"))]
    Bytes(&'a ByteSlice),
    /// Cryptographic Seed.
    #[doc(alias("crypto-seed"))]
    CryptoSeed(crypto_seed::Seed<'a>),
    /// Hierarchical Deterministic Keys.
    #[doc(alias("crypto-hdkey"))]
    CryptoHDKey(crypto_hdkey::BaseHDKey<'a, C>),
    /// Metadata for the complete or partial derivation path of a key.
    #[doc(alias("crypto-keypath"))]
    CryptoKeypath(crypto_hdkey::CryptoKeypath<C>),
    /// Metadata for the type and use of a cryptocurrency.
    #[doc(alias("crypto-coininfo"))]
    CryptoCoinInfo(crypto_hdkey::CryptoCoinInfo),
    /// Elliptic-Curve key.
    #[doc(alias("crypto-eckey"))]
    CryptoECKey(crypto_eckey::ECKey<'a>),
    /// Crypto currency address.
    #[doc(alias("crypto-address"))]
    CryptoAddress(crypto_address::CryptoAddress<'a>),
    /// Partially Signed Bitcoin Transaction.
    #[doc(alias("crypto-psbt"))]
    CryptoPSBT(&'a ByteSlice),
    /// Request to Airgapped Device.
    #[doc(alias("crypto-request"))]
    CryptoRequest(crypto_request::BaseCryptoRequest<'a, Other>),
}

impl<'a, Other, C> BaseValue<'a, Other, C> {
    /// Construct a new [value](BaseValue) from an uniform resource.
    ///
    /// This function decodes `message` depending on the `ur_type`.
    pub fn from_ur<'t>(ur_type: &'t str, message: &'a [u8]) -> Result<Self, Error<'t>>
    where
        Other: Decode<'a, ()>,
        C: Vec<crypto_hdkey::PathComponent>,
    {
        // NOTE: Please keep in the same order as in BCR-2020-006.
        //
        // Unimplemented entries are not formatted to have clean diffs when
        // implementing each one.  Once all types are implemented the
        // rustfmt::skip attribute should be removed.
        #[rustfmt::skip]
        let ur_type = match ur_type {
            "bytes" => BaseValue::Bytes(minicbor::decode(message)?),
            "cbor-png" |
            "cbor-svg" |
            "cose-sign" |
            "cose-sign1" |
            "cose-encrypt" |
            "cose-encrypt0" |
            "cose-mac" |
            "cose-key" |
            "cose-keyset" |
            "crypto-msg" => return Err(Error::Unimplemented(ur_type)),
            "crypto-seed" => BaseValue::CryptoSeed(minicbor::decode(message)?),
            "crypto-bip39" => return Err(Error::Unimplemented(ur_type)),
            "crypto-slip39" => return Err(Error::Deprecated(ur_type)),
            "crypto-hdkey" => BaseValue::CryptoHDKey(minicbor::decode(message)?),
            "crypto-keypath" => BaseValue::CryptoKeypath(minicbor::decode(message)?),
            "crypto-coin-info" => BaseValue::CryptoCoinInfo(minicbor::decode(message)?),
            "crypto-eckey" => BaseValue::CryptoECKey(minicbor::decode(message)?),
            "crypto-address" => BaseValue::CryptoAddress(minicbor::decode(message)?),
            "crypto-output" |
            "crypto-sskr" => return Err(Error::Unimplemented(ur_type)),
            "crypto-psbt" => BaseValue::CryptoPSBT(minicbor::decode(message)?),
            "crypto-account" => return Err(Error::Unimplemented(ur_type)),
            "crypto-request" => BaseValue::CryptoRequest(minicbor::decode(message)?),
            "crypto-response" => return Err(Error::Unimplemented(ur_type)),
            _ => return Err(Error::UnknownType(ur_type)),
        };

        Ok(ur_type)
    }

    /// Returns the UR type string for this value.
    pub fn ur_type(&self) -> &'static str {
        match self {
            BaseValue::Bytes(_) => "bytes",
            BaseValue::CryptoSeed(_) => "crypto-seed",
            BaseValue::CryptoHDKey(_) => "crypto-hdkey",
            BaseValue::CryptoKeypath(_) => "crypto-keypath",
            BaseValue::CryptoCoinInfo(_) => "crypto-coininfo",
            BaseValue::CryptoECKey(_) => "crypto-eckey",
            BaseValue::CryptoAddress(_) => "crypto-address",
            BaseValue::CryptoPSBT(_) => "crypto-psbt",
            BaseValue::CryptoRequest(_) => "crypto-request",
        }
    }
}

impl<'a, Ctx, Other, C> Encode<Ctx> for BaseValue<'a, Other, C>
where
    Other: Encode<Ctx>,
    C: Vec<crypto_hdkey::PathComponent>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            BaseValue::Bytes(v) => e.bytes(v).map(|_| ())?,
            BaseValue::CryptoSeed(v) => v.encode(e, ctx)?,
            BaseValue::CryptoHDKey(v) => v.encode(e, ctx)?,
            BaseValue::CryptoKeypath(v) => v.encode(e, ctx)?,
            BaseValue::CryptoCoinInfo(v) => v.encode(e, ctx)?,
            BaseValue::CryptoECKey(v) => v.encode(e, ctx)?,
            BaseValue::CryptoPSBT(v) => v.encode(e, ctx)?,
            BaseValue::CryptoAddress(v) => v.encode(e, ctx)?,
            BaseValue::CryptoRequest(v) => v.encode(e, ctx)?,
        }

        Ok(())
    }
}

/// Errors that can happen when decoding UR messages.
#[derive(Debug)]
pub enum Error<'a> {
    /// CBOR decoding error.
    Cbor(minicbor::decode::Error),
    /// Deprecated UR type.
    Deprecated(&'a str),
    /// Unimplemented UR type.
    Unimplemented(&'a str),
    /// Unknown UR type.
    UnknownType(&'a str),
}

impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "cbor decoding error: {e}"),
            Error::Deprecated(ur_type) => {
                write!(f, "deprecated UR type \"{ur_type}\"")
            }
            Error::Unimplemented(ur_type) => {
                write!(f, "unimplemented UR type \"{ur_type}\"")
            }
            Error::UnknownType(ur_type) => {
                write!(f, "unknown UR type \"{ur_type}\"")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<'a> std::error::Error for Error<'a> {}

impl<'a> From<minicbor::decode::Error> for Error<'a> {
    fn from(e: minicbor::decode::Error) -> Self {
        Error::Cbor(e)
    }
}
