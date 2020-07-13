use std::fmt;

use derive_more::{AsRef, Deref, From};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::Zeroize;

use crate::utils::{deserialize_base64, serialize_base64};

/// A zeroizing-on-drop container for a `Vec<u8>` that deserializes from base64.
#[derive(Clone, PartialEq, Eq, Zeroize, Deref, AsRef, From)]
#[zeroize(drop)]
pub struct ByteVec(pub Vec<u8>);

impl fmt::Debug for ByteVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "{:?}", self.0)
        } else {
            write!(f, "ByteVec")
        }
    }
}

impl Serialize for ByteVec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_base64(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for ByteVec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(deserialize_base64(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static BYTES: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
    static BASE64_JSON: &str = "\"AQIDBAUGBw==\"";

    #[test]
    fn test_serde_byte_vec() {
        let b64 = serde_json::to_string(&ByteVec(BYTES.to_vec())).unwrap();
        assert_eq!(b64, BASE64_JSON);
        let bytes: ByteVec = serde_json::from_str(&b64).unwrap();
        assert_eq!(bytes.as_slice(), BYTES);
    }
}
