use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize,
};
use zeroize::{Zeroize, Zeroizing};

/// A zeroizing-on-drop container for a `[u8; N]` that deserializes from base64.
#[derive(Clone, PartialEq, Eq, Serialize, Zeroize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ByteArray<const N: usize>(
    #[serde(serialize_with = "crate::utils::serde_base64::serialize")] [u8; N],
);

impl<const N: usize> std::fmt::Debug for ByteArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::utils::base64_encode(self.as_ref()))
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> std::ops::Deref for ByteArray<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> ByteArray<N> {
    /// An unwrapping version of `try_from_slice`.
    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Self {
        Self::try_from_slice(bytes).unwrap()
    }

    pub fn try_from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, String> {
        let bytes = bytes.as_ref();
        if bytes.len() != N {
            Err(format!("expected {} bytes but got {}", N, bytes.len()))
        } else {
            let mut array = [0u8; N];
            array.copy_from_slice(bytes);
            Ok(Self(array))
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for ByteArray<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Zeroizing::new(crate::utils::serde_base64::deserialize(d)?);
        Self::try_from_slice(&*bytes).map_err(|_| {
            de::Error::invalid_length(bytes.len(), &format!("{} base64-encoded bytes", N).as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static BYTES: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
    static BASE64_JSON: &str = "\"AQIDBAUGBw\"";

    fn get_de() -> serde_json::Deserializer<serde_json::de::StrRead<'static>> {
        serde_json::Deserializer::from_str(BASE64_JSON)
    }

    #[test]
    fn test_serde_byte_array_good() {
        let arr = ByteArray::<7>::try_from_slice(BYTES).unwrap();
        let b64 = serde_json::to_string(&arr).unwrap();
        assert_eq!(b64, BASE64_JSON);
        let bytes: ByteArray<7> = serde_json::from_str(&b64).unwrap();
        assert_eq!(bytes.as_ref(), BYTES);
    }

    #[test]
    fn test_serde_deserialize_byte_array_invalid() {
        let mut de = serde_json::Deserializer::from_str("\"Z\"");
        ByteArray::<0>::deserialize(&mut de).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_long() {
        ByteArray::<6>::deserialize(&mut get_de()).unwrap_err();
    }

    #[test]
    fn test_serde_base64_deserialize_array_short() {
        ByteArray::<8>::deserialize(&mut get_de()).unwrap_err();
    }
}
