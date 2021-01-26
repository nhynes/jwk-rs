use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A zeroizing-on-drop container for a `Vec<u8>` that deserializes from base64.
#[derive(Clone, PartialEq, Eq, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ByteVec(#[serde(with = "crate::utils::serde_base64")] Vec<u8>);

impl std::fmt::Debug for ByteVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::utils::base64_encode(&self.0))
    }
}

impl<T: Into<Vec<u8>>> From<T> for ByteVec {
    fn from(into_vec: T) -> Self {
        Self(into_vec.into())
    }
}

impl AsRef<[u8]> for ByteVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for ByteVec {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static BYTES: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
    static BASE64_JSON: &str = "\"AQIDBAUGBw\"";

    #[test]
    fn test_serde_byte_vec() {
        let b64 = serde_json::to_string(&ByteVec(BYTES.to_vec())).unwrap();
        assert_eq!(b64, BASE64_JSON);
        let bytes: ByteVec = serde_json::from_str(&b64).unwrap();
        assert_eq!(bytes.as_ref(), BYTES);
    }
}
