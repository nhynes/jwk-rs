use std::fmt;

use derive_more::{AsRef, Deref, From};
use zeroize::Zeroize;

/// A zeroizing-on-drop container for a `Vec<u8>` that deserializes from base64.
#[derive(Clone, PartialEq, Eq, Zeroize, Serialize, Deserialize, Deref, AsRef, From)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ByteVec(#[serde(with = "crate::utils::serde_base64")] pub Vec<u8>);

impl fmt::Debug for ByteVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "{:?}", self.0)
        } else {
            write!(f, "ByteVec")
        }
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
