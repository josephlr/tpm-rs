use crate::{Marshal, Tpm2bDigest, Unmarshal, errors::UnmarshalError};

/// Random bytes returned by the RNG
#[doc(alias("GetRandom_Out"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct GetRandom<'a> {
    /// The generated random bytes.
    pub random_bytes: Tpm2bDigest<'a>,
}

// *** Marshal/Unmarshal implementations ***

impl<'a> Marshal for GetRandom<'a> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; GetRandom::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; Tpm2bDigest::MAX_SIZE]) -> usize {
        self.random_bytes.marshal(dst)
    }
}
impl<'a> Unmarshal<'a> for GetRandom<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            random_bytes: Tpm2bDigest::unmarshal(src)?,
        })
    }
}
