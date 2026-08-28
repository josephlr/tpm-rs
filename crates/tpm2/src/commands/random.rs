//! TPM 2.0 Random Number Generator Commands
//!
//! This module implements the "Random Number Generator" commands defined in
//! **Section 16** of the TPM 2.0 Specification.
//!
//! These commands allow drawing entropy/random bytes from the TPM and stirring external
//! entropy back into the state.
//!
//! Each command includes its corresponding request parameters, handle list,
//! response parameters, and [`Command`] trait implementation.

use crate::{errors::UnmarshalError, *};

/// [TPM2.0 1.83] 16.1 TPM2_GetRandom (Command)
#[doc(alias = "TPM2_GetRandom")]
#[doc(alias = "GetRandom_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetRandom {
    pub bytes_requested: u16,
}
impl Command for GetRandom {
    const CMD_CODE: TpmCc = TpmCc::GetRandom;
    type Response<'a> = GetRandomRsp;
}
impl Marshal for GetRandom {
    const MAX_SIZE: usize = u16::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.bytes_requested.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for GetRandom {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            bytes_requested: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 16.1 TPM2_GetRandom (Response)
#[doc(alias = "GetRandom_Out")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct GetRandomRsp {
    pub random_bytes: Tpm2bDigest,
}
impl Marshal for GetRandomRsp {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.random_bytes.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for GetRandomRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            random_bytes: Unmarshal::unmarshal(src)?,
        })
    }
}

/// [TPM2.0 1.83] 16.2 TPM2_StirRandom (Command)
#[doc(alias = "TPM2_StirRandom")]
#[doc(alias = "StirRandom_In")]
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
pub struct StirRandom {
    pub in_data: Tpm2bSensitiveData,
}
impl Command for StirRandom {
    const CMD_CODE: TpmCc = TpmCc::StirRandom;
    type Response<'a> = ();
}
impl Marshal for StirRandom {
    const MAX_SIZE: usize = Tpm2bSensitiveData::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.in_data.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for StirRandom {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            in_data: Unmarshal::unmarshal(src)?,
        })
    }
}
