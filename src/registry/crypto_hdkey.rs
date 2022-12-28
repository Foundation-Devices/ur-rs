//! HD Key.

use core::{num::NonZeroU32, ops::Range};

use minicbor::data::Tag;
use minicbor::encode::Write;
use minicbor::{bytes::DecodeBytes, data::Type, decode::Error, Decode, Decoder, Encode, Encoder};

use crate::collections::Vec;

/// Default type for [`BaseHDKey`].
#[cfg(feature = "alloc")]
pub type HDKey<'a> = BaseHDKey<'a, alloc::vec::Vec<PathComponent>>;

/// HD Key.
#[doc(alias("hd-key"))]
#[derive(Debug, Eq, PartialEq)]
pub enum BaseHDKey<'a, C> {
    /// Master key.
    MasterKey(MasterKey),
    /// Derived key.
    DerivedKey(DerivedKey<'a, C>),
}

impl<'b, Ctx, C: Vec<PathComponent>> Decode<'b, Ctx> for BaseHDKey<'b, C> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, Error> {
        if MasterKey::decode(&mut d.probe(), ctx).is_ok() {
            return Ok(BaseHDKey::MasterKey(MasterKey::decode(d, ctx)?));
        }

        if DerivedKey::<C>::decode(&mut d.probe(), ctx).is_ok() {
            return Ok(BaseHDKey::DerivedKey(DerivedKey::decode(d, ctx)?));
        }

        Err(Error::message(
            "couldn't decode as master-key or derived-key",
        ))
    }
}

impl<'a, Ctx, C: Vec<PathComponent>> Encode<Ctx> for BaseHDKey<'a, C> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            BaseHDKey::MasterKey(master_key) => master_key.encode(e, ctx),
            BaseHDKey::DerivedKey(derived_key) => derived_key.encode(e, ctx),
        }
    }
}

/// A master key.
#[doc(alias("master-key"))]
#[derive(Debug, Eq, PartialEq)]
pub struct MasterKey {
    /// Key date bytes.
    pub key_data: [u8; 33],
    /// Chain code bytes.
    pub chain_code: [u8; 32],
}

impl<'b, C> Decode<'b, C> for MasterKey {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut is_master = None;
        let mut key_data = None;
        let mut chain_code = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => is_master = Some(d.bool()?),
                    3 => key_data = Some(DecodeBytes::decode_bytes(d, ctx)?),
                    4 => chain_code = Some(DecodeBytes::decode_bytes(d, ctx)?),
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

        match is_master {
            Some(true) => (),
            Some(false) => return Err(Error::message("is-master is false")),
            None => return Err(Error::message("is-master is not present")),
        }

        Ok(Self {
            key_data: key_data.ok_or_else(|| Error::message("key-data is not present"))?,
            chain_code: chain_code.ok_or_else(|| Error::message("chain-code is not present"))?,
        })
    }
}

impl<C> Encode<C> for MasterKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(3)?
            .u8(1)?
            .bool(true)?
            .u8(3)?
            .bytes(&self.key_data)?
            .u8(4)?
            .bytes(&self.chain_code)?;

        Ok(())
    }
}

/// A derived key.
#[doc(alias("derived-key"))]
#[derive(Debug, Eq, PartialEq)]
pub struct DerivedKey<'a, C> {
    /// `true` if key is private, `false` if public.
    pub is_private: bool,
    /// Key data bytes.
    pub key_data: [u8; 33],
    /// Optional chain code.
    pub chain_code: Option<[u8; 32]>,
    /// How the key is to be used.
    pub use_info: Option<CryptoCoinInfo>,
    /// How the key was derived.
    pub origin: Option<CryptoKeypath<C>>,
    /// What children should/can be derived from this.
    pub children: Option<CryptoKeypath<C>>,
    /// The fingerprint of this key's direct ancestor.
    pub parent_fingerprint: Option<NonZeroU32>,
    /// A short name for this key.
    pub name: Option<&'a str>,
    /// An arbitrary amount of text describing the key.
    pub note: Option<&'a str>,
}

impl<'b, Ctx, C: Vec<PathComponent>> Decode<'b, Ctx> for DerivedKey<'b, C> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, Error> {
        let mut is_private = false;
        let mut key_data = None;
        let mut chain_code = None;
        let mut use_info = None;
        let mut origin = None;
        let mut children = None;
        let mut parent_fingerprint = None;
        let mut name = None;
        let mut note = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    2 => is_private = d.bool()?,
                    3 => key_data = Some(DecodeBytes::decode_bytes(d, ctx)?),
                    4 => chain_code = Some(DecodeBytes::decode_bytes(d, ctx)?),
                    5 => match d.tag()? {
                        Tag::Unassigned(305) => use_info = Some(CryptoCoinInfo::decode(d, ctx)?),
                        _ => return Err(Error::message("invalid tag for crypto-coininfo")),
                    },
                    6 => match d.tag()? {
                        Tag::Unassigned(304) => origin = Some(CryptoKeypath::decode(d, ctx)?),
                        _ => return Err(Error::message("invalid tag for crypto-keypath")),
                    },
                    7 => match d.tag()? {
                        Tag::Unassigned(304) => children = Some(CryptoKeypath::decode(d, ctx)?),
                        _ => return Err(Error::message("invalid tag for crypto-keypath")),
                    },
                    8 => {
                        parent_fingerprint = Some(
                            NonZeroU32::new(d.u32()?)
                                .ok_or_else(|| Error::message("parent-fingerprint is zero"))?,
                        )
                    }
                    9 => name = Some(d.str()?),
                    10 => note = Some(d.str()?),
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
            is_private,
            key_data: key_data.ok_or_else(|| Error::message("key-data is not present"))?,
            chain_code,
            use_info,
            origin,
            children,
            parent_fingerprint,
            name,
            note,
        })
    }
}

impl<'a, Ctx, C: Vec<PathComponent>> Encode<Ctx> for DerivedKey<'a, C> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len = self.is_private as u64
            + 1
            + self.chain_code.is_some() as u64
            + self.use_info.is_some() as u64
            + self.origin.is_some() as u64
            + self.children.is_some() as u64
            + self.parent_fingerprint.is_some() as u64
            + self.name.is_some() as u64
            + self.note.is_some() as u64;

        e.map(len)?;

        if self.is_private {
            e.u8(2)?.bool(self.is_private)?;
        }

        e.u8(3)?.bytes(&self.key_data)?;

        if let Some(ref chain_code) = self.chain_code {
            e.u8(4)?.bytes(chain_code)?;
        }

        if let Some(ref use_info) = self.use_info {
            e.u8(5)?.tag(Tag::Unassigned(305))?;
            use_info.encode(e, ctx)?;
        }

        if let Some(ref origin) = self.origin {
            e.u8(6)?.tag(Tag::Unassigned(304))?;
            origin.encode(e, ctx)?;
        }

        if let Some(ref children) = self.children {
            e.u8(7)?.tag(Tag::Unassigned(304))?;
            children.encode(e, ctx)?;
        }

        if let Some(parent_fingerprint) = self.parent_fingerprint {
            e.u8(8)?.u32(parent_fingerprint.get())?;
        }

        if let Some(name) = self.name {
            e.u8(9)?.str(name)?;
        }

        if let Some(note) = self.note {
            e.u8(10)?.str(note)?;
        }

        Ok(())
    }
}

/// Metadata for the type and use of a cryptocurrency.
#[doc(alias("crypto-coininfo"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CryptoCoinInfo {
    /// Coin type.
    pub coin_type: CoinType,
    /// Network identifier.
    ///
    /// `mainnet` is the general for all currencies.
    ///
    /// All others are coin-specific value.
    pub network: u64,
}

impl CryptoCoinInfo {
    /// Tag for embedding [`CryptoCoinInfo`] in other types.
    pub const TAG: Tag = Tag::Unassigned(305);

    /// Construct a new [`CryptoCoinInfo`].
    pub const fn new(coin_type: CoinType, network: u64) -> Self {
        Self { coin_type, network }
    }
}

impl<'b, C> Decode<'b, C> for CryptoCoinInfo {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut coin_type = None;
        let mut network = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => coin_type = Some(CoinType::decode(d, ctx)?),
                    2 => network = Some(d.u64()?),
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
            coin_type: coin_type.unwrap_or(CoinType::BTC),
            network: network.unwrap_or(0),
        })
    }
}

impl<C> Encode<C> for CryptoCoinInfo {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let is_not_default_coin_type = self.coin_type != CoinType::BTC;
        let is_not_default_network = self.network != 0;
        let len = is_not_default_coin_type as u64 + is_not_default_network as u64;

        e.map(len)?;

        if is_not_default_coin_type {
            e.u8(1)?;
            self.coin_type.encode(e, ctx)?;
        }

        if is_not_default_network {
            e.u8(2)?.u64(self.network)?;
        }

        Ok(())
    }
}

/// Values come from [SLIP-44].
///
/// [SLIP-44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CoinType {
    /// Bitcoin.
    BTC,
    /// Ethereum.
    ETH,
    /// Unassigned coin types.
    Unassigned(u32),
}

impl<'b, C> Decode<'b, C> for CoinType {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        d.u32().map(CoinType::from)
    }
}

impl<C> Encode<C> for CoinType {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u32(u32::from(*self))?;
        Ok(())
    }
}

impl From<u32> for CoinType {
    fn from(n: u32) -> Self {
        #[rustfmt::skip]
        let coin_type = match n {
            0x00 => CoinType::BTC,
            0x3c => CoinType::ETH,
            n  => CoinType::Unassigned(n) ,
        };

        coin_type
    }
}

impl From<CoinType> for u32 {
    fn from(coin_type: CoinType) -> Self {
        #[rustfmt::skip]
        let n = match coin_type {
            CoinType::BTC           => 0x00,
            CoinType::ETH           => 0x3c,
            CoinType::Unassigned(n) => n,
        };

        n
    }
}

/// Metadata for the complete or partial derivation path of a key.
#[doc(alias("crypto-keypath"))]
#[derive(Debug, Eq, PartialEq)]
pub struct CryptoKeypath<C> {
    /// Path components.
    pub components: C,
    /// Fingerprint from the ancestor key.
    pub source_fingerprint: Option<NonZeroU32>,
    /// How many derivations this key is from the master (which is 0).
    pub depth: Option<u8>,
}

impl<C: Vec<PathComponent>> CryptoKeypath<C> {
    /// Create a new key path for a master extended public key.
    ///
    /// The `source_fingerprint` parameter is the fingerprint of the master key.
    pub fn new_master(source_fingerprint: NonZeroU32) -> Self {
        Self {
            components: C::default(),
            source_fingerprint: Some(source_fingerprint),
            depth: Some(0),
        }
    }
}

impl<'b, Ctx, C: Vec<PathComponent>> Decode<'b, Ctx> for CryptoKeypath<C> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, Error> {
        let mut components = None;
        let mut source_fingerprint = None;
        let mut depth = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => {
                        let mut elements = C::default();

                        if let Some(len) = d.array()? {
                            for _ in (0..len).step_by(2) {
                                let elt = PathComponent::decode(d, ctx)?;

                                if elements.try_push(elt).is_err() {
                                    return Err(Error::message(
                                        "not enough capacity to store components",
                                    ));
                                }
                            }
                        } else {
                            while d.datatype()? != Type::Break {
                                let elt = PathComponent::decode(d, ctx)?;

                                if elements.try_push(elt).is_err() {
                                    return Err(Error::message(
                                        "not enough capacity to store components",
                                    ));
                                }
                            }
                        }

                        components = Some(elements)
                    }
                    2 => {
                        source_fingerprint = Some(
                            NonZeroU32::new(d.u32()?)
                                .ok_or_else(|| Error::message("source-fingerprint is zero"))?,
                        )
                    }
                    3 => depth = Some(d.u8()?),
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
            components: components.ok_or_else(|| Error::message("components is missing"))?,
            source_fingerprint,
            depth,
        })
    }
}

impl<Ctx, C: Vec<PathComponent>> Encode<Ctx> for CryptoKeypath<C> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len =
            1 + u64::from(self.source_fingerprint.is_some()) + u64::from(self.depth.is_some());
        e.map(len)?;

        let len = self
            .components
            .len()
            .try_into()
            .map_err(|_| minicbor::encode::Error::message("components does not fit into an u64"))
            .map(|len: u64| len * 2)?;

        e.u8(1)?.array(len)?;
        for elt in self.components.iter() {
            elt.encode(e, ctx)?;
        }

        if let Some(source_fingerprint) = self.source_fingerprint {
            e.u8(2)?.u32(source_fingerprint.get())?;
        }

        if let Some(depth) = self.depth {
            e.u8(3)?.u8(depth)?;
        }

        Ok(())
    }
}

#[cfg(feature = "bitcoin")]
impl<'a, C: Vec<PathComponent>> TryFrom<&'a bitcoin::util::bip32::DerivationPath>
    for CryptoKeypath<C>
{
    type Error = crate::collections::TryReserveError;

    fn try_from(
        derivation_path: &'a bitcoin::util::bip32::DerivationPath,
    ) -> Result<Self, Self::Error> {
        let mut components = C::default();

        for &number in derivation_path {
            components.try_push(number.into())?;
        }

        Ok(Self {
            components,
            source_fingerprint: None,
            depth: None,
        })
    }
}

/// A derivation path component.
#[doc(alias("path-component"))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathComponent {
    /// The child number.
    pub number: ChildNumber,
    /// Hardened key?
    pub is_hardened: bool,
}

impl<'b, C> Decode<'b, C> for PathComponent {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let number = match d.datatype()? {
            Type::U8 | Type::U16 | Type::U32 => ChildNumber::Number(d.u32()?),
            Type::Array => {
                let mut array = d.array_iter::<u32>()?;
                let low = array
                    .next()
                    .ok_or_else(|| Error::message("low child-index not present"))??;
                let high = array
                    .next()
                    .ok_or_else(|| Error::message("high child-index not present"))??;
                if array.next().is_some() {
                    return Err(Error::message("invalid child-index-range size"));
                }

                ChildNumber::Range(low..high)
            }
            _ => return Err(Error::message("unknown child number")),
        };

        Ok(Self {
            number,
            is_hardened: d.bool()?,
        })
    }
}

impl<C> Encode<C> for PathComponent {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self.number {
            ChildNumber::Number(n) => e.u32(n)?,
            ChildNumber::Range(ref range) => e.array(2)?.u32(range.start)?.u32(range.end)?,
        };

        e.bool(self.is_hardened)?;

        Ok(())
    }
}

#[cfg(feature = "bitcoin")]
impl From<bitcoin::util::bip32::ChildNumber> for PathComponent {
    fn from(number: bitcoin::util::bip32::ChildNumber) -> Self {
        match number {
            bitcoin::util::bip32::ChildNumber::Normal { index } => PathComponent {
                number: ChildNumber::Number(index),
                is_hardened: false,
            },
            bitcoin::util::bip32::ChildNumber::Hardened { index } => PathComponent {
                number: ChildNumber::Number(index),
                is_hardened: true,
            },
        }
    }
}

/// The child number of a path component.
// TODO: add wildcard support.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChildNumber {
    /// A single child number.
    Number(u32),
    /// A range of child numbers.
    Range(Range<u32>),
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use bitcoin::{util::bip32::ExtendedPrivKey, PrivateKey};

    use super::*;
    use crate::to_string;

    #[test]
    fn test_example_1() {
        const MASTER_KEY: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        const EXPECTED_CBOR: &str = "A301F503582100E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35045820873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508";
        const EXPECTED_UR: &str = "ur:crypto-hdkey/otadykaxhdclaevswfdmjpfswpwkahcywspsmndwmusoskprbbehetchsnpfcybbmwrhchspfxjeecaahdcxltfszmlyrtdlgmhfcnzcctvwcmkbpsftgonbgauefsehgrqzdmvodizmweemtlaybakiylat";

        let master_key = ExtendedPrivKey::from_str(MASTER_KEY).unwrap();
        let expected_cbor = hex::decode(EXPECTED_CBOR).unwrap();

        let private_key = PrivateKey::new(master_key.private_key.clone(), master_key.network);
        let mut key_data = [0; 33];
        key_data[1..33].copy_from_slice(&private_key.to_bytes());

        let expected_hdkey = HDKey::MasterKey(MasterKey {
            key_data,
            chain_code: master_key.chain_code.to_bytes(),
        });

        let hdkey: HDKey = minicbor::decode(&expected_cbor).unwrap();
        assert_eq!(hdkey, expected_hdkey);

        let cbor = minicbor::to_vec(&hdkey).unwrap();
        assert_eq!(cbor, expected_cbor);

        let ur = to_string("crypto-hdkey", &cbor);
        assert_eq!(&ur, EXPECTED_UR);
    }

    #[test]
    #[cfg(feature = "bitcoin")]
    fn test_example_2() {
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

        const SEED: &str = "d7074d5bdc46af55655244dd5a9d554d7779442d6f4b5a95c257878020188a64";
        const PATH: &str = "m/44'/1'/1'/0/1";
        const DERIVED_KEY: &str = "tpubDHW3GtnVrTatx38EcygoSf9UhUd9Dx1rht7FAL8unrMo8r2NWhJuYNqDFS7cZFVbDaxJkV94MLZAr86XFPsAPYcoHWJ7sWYsrmHDw5sKQ2K";
        const EXPECTED_CBOR: &str = "A5035821026FE2355745BB2DB3630BBC80EF5D58951C963C841F54170BA6E5C12BE7FC12A6045820CED155C72456255881793514EDC5BD9447E7F74ABB88C6D6B6480FD016EE8C8505D90131A1020106D90130A1018A182CF501F501F500F401F4081AE9181CF3";
        const EXPECTED_UR: &str = "ur:crypto-hdkey/onaxhdclaojlvoechgferkdpqdiabdrflawshlhdmdcemtfnlrctghchbdolvwsednvdztbgolaahdcxtottgostdkhfdahdlykkecbbweskrymwflvdylgerkloswtbrpfdbsticmwylklpahtaadehoyaoadamtaaddyoyadlecsdwykadykadykaewkadwkaycywlcscewfihbdaehn";

        let secp = Secp256k1::new();

        let expected_cbor = hex::decode(EXPECTED_CBOR).unwrap();
        let seed = hex::decode(SEED).unwrap();
        let master_key = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &seed).unwrap();

        let path = DerivationPath::from_str(&PATH).unwrap();
        let derived_key = master_key.derive_priv(&secp, &path).unwrap();
        let derived_key = ExtendedPubKey::from_priv(&secp, &derived_key);
        assert_eq!(&derived_key.to_string(), DERIVED_KEY);

        let fingerprint = u32::from_be_bytes(derived_key.parent_fingerprint.to_bytes());

        let expected_hdkey = HDKey::DerivedKey(DerivedKey {
            is_private: false,
            key_data: derived_key.public_key.serialize(),
            chain_code: Some(derived_key.chain_code.to_bytes()),
            use_info: Some(CryptoCoinInfo {
                coin_type: CoinType::BTC,
                network: 1, // testnet-btc
            }),
            origin: Some(CryptoKeypath::try_from(&path).unwrap()),
            children: None,
            parent_fingerprint: Some(NonZeroU32::new(fingerprint).unwrap()),
            name: None,
            note: None,
        });
        let hdkey: HDKey = minicbor::decode(&expected_cbor).unwrap();
        assert_eq!(hdkey, expected_hdkey);

        let cbor = minicbor::to_vec(&hdkey).unwrap();
        assert_eq!(cbor, expected_cbor);

        let ur = to_string("crypto-hdkey", &cbor);
        assert_eq!(&ur, EXPECTED_UR);
    }
}
