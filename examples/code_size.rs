#![no_std]

use tpm2::errors::{MarshalError, UnmarshalError};
use tpm2::marshal::{EccCurves, Limits, Marshal, RsaKeySizes, TpmaHashAlgs, Unmarshal};
use tpm2::{TpmiAlgHash::*, TpmiEccCurve, TpmtHa};

pub struct Small;
impl Limits for Small {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_alg_list(&[Sha256]);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::NONE;
    const ECC_CURVES: EccCurves = EccCurves::from_curve_list(&[TpmiEccCurve::NIST_P256]);
}

pub struct Medium;
impl Limits for Medium {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs::from_alg_list(&[Sha1, Sha256]);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::from_key_bits_list(&[2048]);
    const ECC_CURVES: EccCurves = EccCurves::from_curve_list(&[
        TpmiEccCurve::NIST_P256,
        TpmiEccCurve::NIST_P384,
        TpmiEccCurve::BN_P256,
    ]);
}

pub struct Large;
impl Limits for Large {
    const HASH_ALGS: TpmaHashAlgs = TpmaHashAlgs(u32::MAX);
    const RSA_KEY_SIZES: RsaKeySizes = RsaKeySizes::ALL;
    const ECC_CURVES: EccCurves = EccCurves::ALL;
}

type L = Large;

pub fn marshal1(ha: TpmtHa, buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal::<L>(buf)?;
    Ok(())
}
pub fn marshal2(ha: TpmtHa, mut buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal2::<L>(&mut buf)
}
pub fn marshal3(ha: TpmtHa, buf: &mut [u8]) -> Result<(), MarshalError> {
    ha.marshal3::<L>(buf)?;
    Ok(())
}

pub fn unmarshal1(buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal::<L>(buf)?;
    Ok(ha)
}
pub fn unmarshal2(mut buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal2::<L>(&mut buf)?;
    Ok(ha)
}
pub fn unmarshal3(buf: &[u8]) -> Result<TpmtHa<'_>, UnmarshalError> {
    let mut ha = TpmtHa::Sha256(&[0; Sha256.digest_size()]);
    ha.unmarshal3::<L>(buf)?;
    Ok(ha)
}
