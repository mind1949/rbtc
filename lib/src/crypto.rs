use ecdsa::{signature::Signer, Signature as ECDSASignature, SigningKey, VerifyingKey};
use k256::Secp256k1;
use serde::{Deserialize, Serialize};

pub struct MerkleRoot;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Signature(ECDSASignature<Secp256k1>);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PublicKey(pub VerifyingKey<Secp256k1>);

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PrivateKey(#[serde(with = "signkey_serde")] pub SigningKey<Secp256k1>);

impl PrivateKey {
    pub fn new_key() -> Self {
        Self(SigningKey::random(&mut rand::thread_rng()))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().clone())
    }
}

mod signkey_serde {
    use serde::Deserialize;

    pub fn serialize<S>(
        key: &super::SigningKey<super::Secp256k1>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<super::SigningKey<super::Secp256k1>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        Ok(super::SigningKey::from_slice(&bytes).unwrap())
    }
}
