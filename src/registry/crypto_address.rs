//! Cryptocurrency addresses.

use crate::registry::crypto_hdkey::CryptoCoinInfo;
use minicbor::data::Type;
use minicbor::decode::Error;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

/// A cryptocurrency address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CryptoAddress<'a> {
    /// Coin information.
    pub info: Option<CryptoCoinInfo>,
    /// Address type if applicable.
    pub address_type: Option<AddressType>,
    /// The address data.
    pub data: &'a [u8],
}

impl<'b, C> Decode<'b, C> for CryptoAddress<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut info = None;
        let mut address_type = None;
        let mut data = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => {
                        if CryptoCoinInfo::TAG != d.tag()? {
                            return Err(Error::message("crypto-coin-info tag is invalid"));
                        }

                        info = Some(CryptoCoinInfo::decode(d, ctx)?);
                    }
                    2 => address_type = Some(AddressType::decode(d, ctx)?),
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
            info,
            address_type,
            data: data.ok_or_else(|| Error::message("data is missing"))?,
        })
    }
}

impl<'a, C> Encode<C> for CryptoAddress<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len = self.info.is_some() as u64 + self.address_type.is_some() as u64 + 1;
        e.map(len)?;

        if let Some(ref info) = self.info {
            e.u8(1)?.tag(CryptoCoinInfo::TAG)?;
            info.encode(e, ctx)?;
        }

        if let Some(ref address_type) = self.address_type {
            e.u8(2)?;
            address_type.encode(e, ctx)?;
        }

        e.u8(3)?.bytes(self.data)?;

        Ok(())
    }
}

/// Bitcoin (and similar cryptocurrencies) address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Pay to Public Key Hash.
    P2PKH,
    /// Pay to Script Hash.
    P2SH,
    /// Pay to Witness Public Key Hash.
    P2WPKH,
}

impl TryFrom<u8> for AddressType {
    type Error = InvalidAddressType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => AddressType::P2PKH,
            1 => AddressType::P2SH,
            2 => AddressType::P2WPKH,
            _ => {
                return Err(InvalidAddressType {
                    invalid_type: value,
                })
            }
        })
    }
}

impl From<AddressType> for u8 {
    fn from(value: AddressType) -> Self {
        match value {
            AddressType::P2PKH => 0,
            AddressType::P2SH => 1,
            AddressType::P2WPKH => 2,
        }
    }
}

/// Error that can happen during conversion from an unsigned integer to an
/// [`AddressType`].
#[derive(Debug)]
pub struct InvalidAddressType {
    /// The invalid type.
    pub invalid_type: u8,
}

impl<'b, C> Decode<'b, C> for AddressType {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        AddressType::try_from(d.u8()?).map_err(|_| Error::message("invalid address type"))
    }
}

impl<C> Encode<C> for AddressType {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8((*self).into())?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::registry::crypto_hdkey::CoinType;

    #[test]
    #[cfg(feature = "bitcoin")]
    fn test_example_1() {
        use bitcoin::Address;
        use core::str::FromStr;

        const ADDRESS: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        const EXPECTED_CBOR: &str = "A1035477BFF20C60E522DFAA3350C39B030A5D004E839A";

        let address = Address::from_str(ADDRESS).unwrap();
        let expected_cbor = hex::decode(EXPECTED_CBOR).unwrap();

        let crypto_address = CryptoAddress {
            info: None,
            address_type: None,
            data: address.payload.as_bytes(),
        };

        let cbor = minicbor::to_vec(&crypto_address).unwrap();
        assert_eq!(cbor, expected_cbor);

        let decoded = minicbor::decode(&cbor).unwrap();
        assert_eq!(crypto_address, decoded);
    }

    #[test]
    fn test_example_2() {
        const ADDRESS: &str = "0x81b7E08F65Bdf5648606c89998A9CC8164397647";
        const EXPECTED_CBOR: &str =
            "A201D90131A201183C0201035481B7E08F65BDF5648606C89998A9CC8164397647";

        let address = hex::decode(ADDRESS.strip_prefix("0x").unwrap()).unwrap();
        let expected_cbor = hex::decode(EXPECTED_CBOR).unwrap();

        let crypto_address = CryptoAddress {
            info: CryptoCoinInfo::new(CoinType::ETH, 1).into(),
            address_type: None,
            data: &address,
        };

        let cbor = minicbor::to_vec(&crypto_address).unwrap();
        assert_eq!(cbor, expected_cbor);

        let decoded = minicbor::decode(&cbor).unwrap();
        assert_eq!(crypto_address, decoded);
    }
}
