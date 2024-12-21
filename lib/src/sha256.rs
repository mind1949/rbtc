use std::fmt;

use crate::U256;
use serde::{Deserialize, Serialize};
use sha256::digest;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash(U256);

impl Hash {
    // hash anything that can be serde Serialized via ciborium
    pub fn hash<T: serde::Serialize>(data: &T) -> Self {
        let mut serialized: Vec<u8> = vec![];
        if let Err(e) = ciborium::into_writer(data, &mut serialized) {
            panic!(
                "Failed to serialize data: {:?}. \
                This should not happen",
                e
            );
        }

        let hash = digest(&serialized);
        let hash_bytes = hex::decode(hash).unwrap();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Self(U256::from(hash_array))
    }

    // convert to bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes: Vec<u8> = vec![0; 32];
        self.0.to_little_endian(&mut bytes);
        bytes.as_slice().try_into().unwrap()
    }

    // check if a hash matches a target
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    // zero hash
    pub fn zero() -> Self {
        Hash(U256::zero())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
