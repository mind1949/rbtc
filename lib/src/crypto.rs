use crate::sha256::Hash;
use crate::util::Saveable;
use ecdsa::signature::Verifier;
use ecdsa::{signature::SignerMut, Signature as ECDSASignature, SigningKey, VerifyingKey};
use k256::pkcs8::EncodePublicKey;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleRoot;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Signature(pub ECDSASignature<Secp256k1>);

impl Signature {
    // sign a crate::types::TransactionOutput from its Sha256 hash
    pub fn sign_output(output_hash: &Hash, private_key: &mut PrivateKey) -> Self {
        let signing_key = &mut private_key.0;
        let signature = signing_key.sign(&output_hash.as_bytes());
        Signature(signature)
    }

    // verify a signature
    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        public_key
            .0
            .verify(&output_hash.as_bytes(), &self.0)
            .is_ok()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PublicKey(VerifyingKey<Secp256k1>);

impl Saveable for PublicKey {
    fn load<I: std::io::Read>(mut reader: I) -> std::io::Result<Self> {
        // read PEM-encoded public key into string
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        // decode the public key from PEM
        let public_key = buf
            .parse()
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to parse PublicKey"))?;
        Ok(PublicKey(public_key))
    }
    fn save<O: std::io::Write>(&self, mut writer: O) -> std::io::Result<()> {
        let s = self
            .0
            .to_public_key_pem(Default::default())
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to serialize PublicKey"))?;
        writer.write_all(s.as_bytes())?;
        Ok(())
    }
}

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

impl Saveable for PrivateKey {
    fn load<I: std::io::Read>(reader: I) -> std::io::Result<Self> {
        ciborium::de::from_reader(reader)
            .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Failed to deserialize PrivateKey"))
    }
    fn save<O: std::io::Write>(&self, writer: O) -> std::io::Result<()> {
        ciborium::ser::into_writer(self, writer).map_err(|_| {
            IoError::new(IoErrorKind::InvalidData, "Failed to serialize PrivateKey")
        })?;
        Ok(())
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
