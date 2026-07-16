use crate::{Alg, Marshal, TpmiAlgHash, Unmarshal, errors::UnmarshalError, unmarshal_array_ref};
use TpmiAlgHash::*;

/// `TPMT_HA`
///
/// There is no type for `TPMU_HA` in this crate, use this type instead.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum TpmtHa<'a> {
    Sha1(&'a [u8; Sha1.digest_size()]),
    Sha256(&'a [u8; Sha256.digest_size()]),
    Sha384(&'a [u8; Sha384.digest_size()]),
    Sha512(&'a [u8; Sha512.digest_size()]),
    // TODO: Add other Hash Algs
}

impl<'a> TpmtHa<'a> {
    /// Returns the [`TpmiAlgHash`] corresponding to this digest.
    pub const fn hash_alg(self) -> TpmiAlgHash {
        match self {
            Self::Sha1(_) => Sha1,
            Self::Sha256(_) => Sha256,
            Self::Sha384(_) => Sha384,
            Self::Sha512(_) => Sha512,
        }
    }

    /// Returns the underlying digest byte slice.
    pub fn digest(self) -> &'a [u8] {
        match self {
            Self::Sha1(d) => d,
            Self::Sha256(d) => d,
            Self::Sha384(d) => d,
            Self::Sha512(d) => d,
        }
    }
}

const EMPTY_SHA256: &[u8; Sha256.digest_size()] = &[0; Sha256.digest_size()];

impl<'a> Default for TpmtHa<'a> {
    fn default() -> Self {
        Self::Sha256(EMPTY_SHA256)
    }
}

// *** Marshal/Unmarshal implementations ***

impl<'a> Marshal for TpmtHa<'a> {
    const MAX_SIZE: usize = Alg::MAX_SIZE + TpmiAlgHash::MAX_DIGEST_SIZE;
    type MaxBuffer = [u8; TpmtHa::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; TpmtHa::MAX_SIZE]) -> usize {
        let hash_alg = Alg::from(self.hash_alg());
        let len = hash_alg.marshal((&mut dst[..Alg::MAX_SIZE]).try_into().unwrap());
        let digest = self.digest();
        dst[len..len + digest.len()].copy_from_slice(digest);
        len + digest.len()
    }
}

impl<'a> Unmarshal<'a> for TpmtHa<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let alg = TpmiAlgHash::unmarshal(src)?;
        match alg {
            TpmiAlgHash::Sha1 => Ok(TpmtHa::Sha1(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha256 => Ok(TpmtHa::Sha256(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha384 => Ok(TpmtHa::Sha384(unmarshal_array_ref(src)?)),
            TpmiAlgHash::Sha512 => Ok(TpmtHa::Sha512(unmarshal_array_ref(src)?)),
            _ => Err(UnmarshalError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpmt_ha_marshal_unmarshal() {
        let digest_bytes = [0xAB; 32];
        let tpmt_ha = TpmtHa::Sha256(&digest_bytes);

        let mut buf = [0u8; TpmtHa::MAX_SIZE];
        let len = tpmt_ha.marshal(&mut buf);
        assert_eq!(len, 2 + 32);

        let mut slice = &buf[..len];
        let unmarshaled = TpmtHa::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled, tpmt_ha);
        assert!(slice.is_empty());
    }
}
