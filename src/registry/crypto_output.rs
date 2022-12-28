use crate::registry::crypto_hdkey::HDKey;

#[doc(alias("key-exp"))]
pub enum KeyExpression<'a> {
    #[doc(alias("crypto-eckey"))]
    CryptoECKey(ECKey),
    #[doc(alias("crypto-hdkey"))]
    CryptoHDKey(HDKey<'a>),
}

pub struct KeyExpressionIterator<'a> {
}

pub enum ScriptExpression<'a> {
    ScriptHash,
    WitnessScriptHash,
    Taproot,

    // Terminal expressions.
    PublicKey(KeyExpression<'a>),
    PublicKeyHash(KeyExpression<'a>),
    WitnessPublicKeyHash(KeyExpression<'a>),
    Combo(KeyExpression<'a>),
    Multisig(Multikey<'a>),
    SortedMultisig(Multikey<'a>),
    Address(CryptoAddress<'a>),
    RawScript(&'a [u8]),
    Cosigner(KeyExpression<'a>),
}

#[derive(Debug, Decode, Encode, Clone)]
#[cbor(map)]
pub struct Multikey<'a> {
    #[cbor(n(1))]
    pub threshold: u64,
    #[cbor(n(2))]
    pub keys: KeyExpressionIterator<'a>,
}

fn test() {
    let pkh = ScriptExpression::PublicKeyHash(ECKey);
}
