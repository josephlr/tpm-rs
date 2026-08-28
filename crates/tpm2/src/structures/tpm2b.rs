use crate::{errors::UnmarshalError, marshal::marshal_helper, *};

pub(crate) fn unmarshal_2b_simple<const CAP: usize>(
    src: &mut &[u8],
) -> Result<(u16, [u8; CAP]), UnmarshalError> {
    let got_size: u16 = Unmarshal::unmarshal(src)?;
    let sz = got_size as usize;
    if sz > CAP || src.len() < sz {
        return Err(UnmarshalError);
    }
    let (slice, rest) = src.split_at(sz);
    *src = rest;
    let mut dest = [0u8; CAP];
    dest[..sz].copy_from_slice(slice);
    Ok((got_size, dest))
}

pub(crate) fn marshal_2b_simple(size: u16, buf: &[u8], max_cap: usize, dst: &mut [u8]) -> usize {
    let sz = size as usize;
    if sz > max_cap || dst.len() < 2 + sz {
        return 0;
    }
    let _ = marshal_helper(&size, dst, 0);
    dst[2..2 + sz].copy_from_slice(&buf[..sz]);
    2 + sz
}

pub trait Tpm2bSimple {
    const MAX_BUFFER_SIZE: usize;
    fn get_size(&self) -> u16;
    fn get_buffer(&self) -> &[u8];
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError>
    where
        Self: Sized;
}

/// Provides conversion to/from a struct type for TPM2B types that don't hold a bytes buffer.
pub trait Tpm2bStruct: Tpm2bSimple {
    type StructType: Marshal + for<'a> Unmarshal<'a>;

    /// Marshals the value into the 2b holder.
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError>
    where
        Self: Sized;

    /// Extracts the struct value from the 2b holder.
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError>;
}

fn tpm2b_to_struct<'a, T: Unmarshal<'a>, B: Tpm2bSimple>(b: &'a B) -> Result<T, UnmarshalError> {
    let mut buf = b.get_buffer();
    let res = Unmarshal::unmarshal(&mut buf)?;
    if !buf.is_empty() {
        return Err(UnmarshalError);
    }
    Ok(res)
}

// ---------------------------------------------------------------------------
// Tpm2bDigest
// ---------------------------------------------------------------------------
/// `TPM2B_DIGEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.2 (Table 87).
///
/// A sized buffer that holds digest values, HMAC keys, auth values, nonces, or seed values.
/// The size cannot exceed the largest digest produced by any hash algorithm implemented on the TPM.
#[doc(alias = "TPM2B_DIGEST")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bDigest {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; Self::MAX_BUFFER_SIZE],
}

impl Default for Tpm2bDigest {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bDigest {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bDigest {
    const MAX_BUFFER_SIZE: usize = TpmtHa::MAX_DIGEST_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bDigest {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bDigest {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

/// `TPM2B_NONCE` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.6 (Table 79).
///
/// Type alias for `Tpm2bDigest` representing a nonce in authorization protocols.
#[doc(alias = "TPM2B_NONCE")]
pub type Tpm2bNonce = Tpm2bDigest;

/// `TPM2B_OPERAND` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.5 (Table 78).
///
/// Type alias for `Tpm2bDigest` representing an operand in cryptographic operations.
#[doc(alias = "TPM2B_OPERAND")]
pub type Tpm2bOperand = Tpm2bDigest;

/// `TPM2B_AUTH` type alias defined in TPM 2.0 Part 2: Structures, Section 10.4.4 (Table 77).
///
/// Type alias for `Tpm2bDigest` representing an authorization value.
#[doc(alias = "TPM2B_AUTH")]
pub type Tpm2bAuth = Tpm2bDigest;

// ---------------------------------------------------------------------------
// Tpm2bTimeout
// ---------------------------------------------------------------------------
/// `TPM2B_TIMEOUT` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.10 (Table 95).
///
/// A sized buffer (up to 8 bytes) used to provide the timeout value for an authorization ticket
/// (such as tickets created by `TPM2_PolicySigned` or `TPM2_PolicySecret`).
#[doc(alias = "TPM2B_TIMEOUT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bTimeout {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; 8],
}
impl Default for Tpm2bTimeout {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bTimeout {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bTimeout {
    const MAX_BUFFER_SIZE: usize = 8;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bTimeout {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bTimeout {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bData
// ---------------------------------------------------------------------------
/// `TPM2B_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.3 (Table 88).
///
/// A sized buffer used for general data parameters (such as key parameters or nonce values)
/// up to the size of a digest.
#[doc(alias = "TPM2B_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bData {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; Self::MAX_BUFFER_SIZE],
}
impl Default for Tpm2bData {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bData {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bData {
    const MAX_BUFFER_SIZE: usize = TpmtHa::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bData {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bData {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bEvent
// ---------------------------------------------------------------------------
/// `TPM2B_EVENT` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.7 (Table 92).
///
/// A sized buffer holding event data passed into `TPM2_PCR_Event` or `TPM2_EventSequenceComplete`.
#[doc(alias = "TPM2B_EVENT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bEvent {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; 1024],
}
impl Default for Tpm2bEvent {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bEvent {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bEvent {
    const MAX_BUFFER_SIZE: usize = 1024;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bEvent {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bEvent {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bMaxBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.8 (Table 93).
///
/// A sized buffer holding up to `TPM2_MAX_DIGEST_BUFFER` bytes, used for bulk data transfer
/// in hash, sequence, and encryption commands.
#[doc(alias = "TPM2B_MAX_BUFFER")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bMaxBuffer {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_DIGEST_BUFFER as usize],
}
impl Default for Tpm2bMaxBuffer {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bMaxBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bMaxBuffer {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_DIGEST_BUFFER as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bMaxBuffer {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bMaxBuffer {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_DIGEST_BUFFER as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bMaxNvBuffer
// ---------------------------------------------------------------------------
/// `TPM2B_MAX_NV_BUFFER` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.9 (Table 94).
///
/// A sized buffer holding up to `TPM2_MAX_NV_BUFFER_SIZE` bytes, used for NV index read and write operations.
#[doc(alias = "TPM2B_MAX_NV_BUFFER")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bMaxNvBuffer {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_NV_BUFFER_SIZE as usize],
}
impl Default for Tpm2bMaxNvBuffer {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bMaxNvBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bMaxNvBuffer {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_NV_BUFFER_SIZE as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bMaxNvBuffer {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bMaxNvBuffer {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_NV_BUFFER_SIZE as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bIv
// ---------------------------------------------------------------------------
/// `TPM2B_IV` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.11 (Table 96).
///
/// A sized buffer holding an initialization vector (IV) for symmetric block ciphers, sized to the
/// largest block size of any implemented symmetric cipher on the TPM.
#[doc(alias = "TPM2B_IV")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bIv {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_SYM_BLOCK_SIZE as usize],
}
impl Default for Tpm2bIv {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bIv {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bIv {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_SYM_BLOCK_SIZE as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bIv {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bIv {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_SYM_BLOCK_SIZE as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bName
// ---------------------------------------------------------------------------
/// `TPM2B_NAME` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.12 (Table 99).
///
/// A sized buffer holding a TPM entity Name (which consists of a 2-byte hash algorithm ID followed
/// by the hash digest of the entity's public area, or a 4-byte handle for permanent entities).
#[doc(alias = "TPM2B_NAME")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bName {
    pub(crate) size: u16,
    pub(crate) name: [u8; Self::MAX_BUFFER_SIZE],
}
impl Default for Tpm2bName {
    fn default() -> Self {
        Self {
            size: 0,
            name: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bName {
    fn as_ref(&self) -> &[u8] {
        &self.name[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bName {
    const MAX_BUFFER_SIZE: usize = TpmtHa::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.name[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.name[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bName {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.name, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bName {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, name: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bAttest
// ---------------------------------------------------------------------------
/// `TPM2B_ATTEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.4.24 (Table 143).
///
/// A sized buffer holding a marshaled `TPMS_ATTEST` structure. This buffer is generated and signed
/// by the TPM during attestation commands (`TPM2_Certify`, `TPM2_Quote`, `TPM2_GetTime`, etc.).
#[doc(alias = "TPM2B_ATTEST")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bAttest {
    pub(crate) size: u16,
    pub(crate) attestation_data: [u8; TpmsAttest::MAX_SIZE],
}
impl Default for Tpm2bAttest {
    fn default() -> Self {
        Self {
            size: 0,
            attestation_data: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bAttest {
    fn as_ref(&self) -> &[u8] {
        &self.attestation_data[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bAttest {
    const MAX_BUFFER_SIZE: usize = TpmsAttest::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.attestation_data[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.attestation_data[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bAttest {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(
            self.size,
            &self.attestation_data,
            Self::MAX_BUFFER_SIZE,
            dst,
        )
    }
}

impl<'a> Unmarshal<'a> for Tpm2bAttest {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            attestation_data: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bAttest {
    type StructType = TpmsAttest;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.attestation_data[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bSymKey
// ---------------------------------------------------------------------------
/// `TPM2B_SYM_KEY` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.6 (Table 153).
///
/// A sized buffer holding a symmetric encryption key value (up to `TPM2_MAX_SYM_KEY_BYTES`).
#[doc(alias = "TPM2B_SYM_KEY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bSymKey {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_SYM_KEY_BYTES as usize],
}
impl Default for Tpm2bSymKey {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bSymKey {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bSymKey {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_SYM_KEY_BYTES as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bSymKey {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bSymKey {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_SYM_KEY_BYTES as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bLabel
// ---------------------------------------------------------------------------
/// `TPM2B_LABEL` structure defined in TPM 2.0 Part 2: Structures, Section 11.1.8 (Table 155).
///
/// A sized buffer holding a label or context string used in key derivation functions (KDF)
/// or protocol parameter generation.
#[doc(alias = "TPM2B_LABEL")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bLabel {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_LABEL_MAX_BUFFER as usize],
}
impl Default for Tpm2bLabel {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bLabel {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bLabel {
    const MAX_BUFFER_SIZE: usize = TPM2_LABEL_MAX_BUFFER as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bLabel {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bLabel {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_LABEL_MAX_BUFFER as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bSensitiveData
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 10.2.17 (Table 160).
///
/// A sized buffer holding sensitive data (such as a symmetric key or private data) for object creation
/// or unsealing operations.
#[doc(alias = "TPM2B_SENSITIVE_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bSensitiveData {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; Self::MAX_BUFFER_SIZE],
}
impl Default for Tpm2bSensitiveData {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bSensitiveData {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bSensitiveData {
    const MAX_BUFFER_SIZE: usize = crate::constants::TPM2_MAX_SYM_DATA as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bSensitiveData {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bSensitiveData {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bSensitiveCreate
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE_CREATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.2 (Table 161).
///
/// A sized buffer wrapping `TPMS_SENSITIVE_CREATE`, containing the user authorization value and sensitive data
/// passed to `TPM2_Create` or `TPM2_CreatePrimary`.
#[doc(alias = "TPM2B_SENSITIVE_CREATE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bSensitiveCreate {
    pub(crate) size: u16,
    pub(crate) sensitive: [u8; TpmsSensitiveCreate::MAX_SIZE],
}
impl Default for Tpm2bSensitiveCreate {
    fn default() -> Self {
        Self {
            size: 0,
            sensitive: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bSensitiveCreate {
    fn as_ref(&self) -> &[u8] {
        &self.sensitive[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bSensitiveCreate {
    const MAX_BUFFER_SIZE: usize = TpmsSensitiveCreate::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.sensitive[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.sensitive[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bSensitiveCreate {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.sensitive, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bSensitiveCreate {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            sensitive: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bSensitiveCreate {
    type StructType = TpmsSensitiveCreate;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.sensitive[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bPublicKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.5 (Table 183).
///
/// A sized buffer holding the modulus of an RSA public key (up to `TPM2_MAX_RSA_KEY_BYTES`).
#[doc(alias = "TPM2B_PUBLIC_KEY_RSA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bPublicKeyRsa {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_RSA_KEY_BYTES as usize],
}
impl Default for Tpm2bPublicKeyRsa {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bPublicKeyRsa {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bPublicKeyRsa {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_RSA_KEY_BYTES as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bPublicKeyRsa {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bPublicKeyRsa {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_RSA_KEY_BYTES as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bPrivateKeyRsa
// ---------------------------------------------------------------------------
/// `TPM2B_PRIVATE_KEY_RSA` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.1.6 (Table 187).
///
/// A sized buffer holding an RSA private prime factor (P or Q).
#[doc(alias = "TPM2B_PRIVATE_KEY_RSA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bPrivateKeyRsa {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; 1536],
}
impl Default for Tpm2bPrivateKeyRsa {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bPrivateKeyRsa {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bPrivateKeyRsa {
    const MAX_BUFFER_SIZE: usize = 1536;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bPrivateKeyRsa {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bPrivateKeyRsa {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bEccParameter
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_PARAMETER` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.1 (Table 188).
///
/// A sized buffer holding a single ECC coordinate or parameter value (X or Y coordinate).
#[doc(alias = "TPM2B_ECC_PARAMETER")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bEccParameter {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_ECC_KEY_BYTES as usize],
}
impl Default for Tpm2bEccParameter {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bEccParameter {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bEccParameter {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_ECC_KEY_BYTES as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bEccParameter {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bEccParameter {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_ECC_KEY_BYTES as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bEccPoint
// ---------------------------------------------------------------------------
/// `TPM2B_ECC_POINT` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.2.2 (Table 190).
///
/// A sized buffer wrapping a `TPMS_ECC_POINT` structure, containing affine X and Y coordinates for an ECC point.
#[doc(alias = "TPM2B_ECC_POINT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bEccPoint {
    pub(crate) size: u16,
    pub(crate) point: [u8; TpmsEccPoint::MAX_SIZE],
}
impl Default for Tpm2bEccPoint {
    fn default() -> Self {
        Self {
            size: 0,
            point: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bEccPoint {
    fn as_ref(&self) -> &[u8] {
        &self.point[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bEccPoint {
    const MAX_BUFFER_SIZE: usize = TpmsEccPoint::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.point[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.point[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bEccPoint {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.point, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bEccPoint {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, point: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bEncryptedSecret
// ---------------------------------------------------------------------------
/// `TPM2B_ENCRYPTED_SECRET` structure defined in TPM 2.0 Part 2: Structures, Section 11.2.4 (Table 197).
///
/// A sized buffer holding an encrypted secret value used for salted auth sessions in `TPM2_StartAuthSession`
/// or key duplication (`TPM2_Duplicate`).
#[doc(alias = "TPM2B_ENCRYPTED_SECRET")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bEncryptedSecret {
    pub(crate) size: u16,
    pub(crate) secret: [u8; Self::MAX_BUFFER_SIZE],
}
impl Default for Tpm2bEncryptedSecret {
    fn default() -> Self {
        Self {
            size: 0,
            secret: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bEncryptedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.secret[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bEncryptedSecret {
    const MAX_BUFFER_SIZE: usize = crate::constants::TPM2_MAX_RSA_KEY_BYTES as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.secret[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.secret[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bEncryptedSecret {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.secret, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bEncryptedSecret {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, secret: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bPublic
// ---------------------------------------------------------------------------
/// `TPM2B_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 212).
///
/// A sized buffer wrapping `TPMT_PUBLIC`, defining the public area of a TPM object (key type, attributes,
/// auth policy, parameters, and public key data).
#[doc(alias = "TPM2B_PUBLIC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bPublic {
    pub(crate) size: u16,
    pub(crate) public_area: [u8; TpmtPublic::MAX_SIZE],
}

impl Default for Tpm2bPublic {
    fn default() -> Self {
        Self {
            size: 0,
            public_area: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}

impl Tpm2bSimple for Tpm2bPublic {
    const MAX_BUFFER_SIZE: usize = TpmtPublic::MAX_SIZE;

    fn get_size(&self) -> u16 {
        self.size
    }

    fn get_buffer(&self) -> &[u8] {
        &self.public_area[..self.get_size() as usize]
    }

    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }

        let mut dest: Self = Self {
            size: buffer.len() as u16,
            public_area: [0; Self::MAX_BUFFER_SIZE],
        };
        dest.public_area[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Tpm2bStruct for Tpm2bPublic {
    type StructType = TpmtPublic;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.public_area[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

impl Marshal for Tpm2bPublic {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.public_area, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bPublic {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        let val = Self {
            size,
            public_area: buf,
        };
        if val.size > 0 {
            let _ = val.to_struct()?;
        }
        Ok(val)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bTemplate
// ---------------------------------------------------------------------------
/// `TPM2B_TEMPLATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.4 (Table 213).
///
/// A sized buffer holding a public area template (`TPMT_PUBLIC`) used in `TPM2_CreateLoaded`
/// to specify key parameters derived from a template.
#[doc(alias = "TPM2B_TEMPLATE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bTemplate {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TpmtPublic::MAX_SIZE],
}
impl Default for Tpm2bTemplate {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bTemplate {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bTemplate {
    const MAX_BUFFER_SIZE: usize = TpmtPublic::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bTemplate {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bTemplate {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}
impl Tpm2bStruct for Tpm2bTemplate {
    type StructType = TpmtPublic;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.buffer[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tpm2bSensitive
// ---------------------------------------------------------------------------
/// `TPM2B_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 217).
///
/// A sized buffer wrapping `TPMT_SENSITIVE`, defining the sensitive/private area of an object
/// (containing the authorization value, seed, and private key material).
#[doc(alias = "TPM2B_SENSITIVE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bSensitive {
    pub(crate) size: u16,
    pub(crate) sensitive_area: [u8; TpmtSensitive::MAX_SIZE],
}
impl Default for Tpm2bSensitive {
    fn default() -> Self {
        Self {
            size: 0,
            sensitive_area: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bSensitive {
    fn as_ref(&self) -> &[u8] {
        &self.sensitive_area[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bSensitive {
    const MAX_BUFFER_SIZE: usize = TpmtSensitive::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.sensitive_area[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.sensitive_area[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bSensitive {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.sensitive_area, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bSensitive {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            sensitive_area: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bSensitive {
    type StructType = TpmtSensitive;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.sensitive_area[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bPrivate
// ---------------------------------------------------------------------------
/// `TPM2B_PRIVATE` structure defined in TPM 2.0 Part 2: Structures, Section 12.2.5 (Table 218).
///
/// A sized buffer holding the encrypted sensitive area (`TPMT_SENSITIVE`) of a TPM object, encrypted under
/// its parent object's key.
#[doc(alias = "TPM2B_PRIVATE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bPrivate {
    pub size: u16,
    pub buffer: [u8; TPM2_MAX_PRIVATE_SIZE],
}
impl Default for Tpm2bPrivate {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bPrivate {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bPrivate {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_PRIVATE_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bPrivate {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bPrivate {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_PRIVATE_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bIdObject
// ---------------------------------------------------------------------------
/// `TPM2B_ID_OBJECT` structure defined in TPM 2.0 Part 2: Structures, Section 12.3 (Table 221).
///
/// A sized buffer wrapping `TPMS_ID_OBJECT`, containing an encrypted credential payload used in `TPM2_ActivateCredential`.
#[doc(alias = "TPM2B_ID_OBJECT")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bIdObject {
    pub(crate) size: u16,
    pub(crate) credential: [u8; TpmsIdObject::MAX_SIZE],
}
impl Default for Tpm2bIdObject {
    fn default() -> Self {
        Self {
            size: 0,
            credential: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bIdObject {
    fn as_ref(&self) -> &[u8] {
        &self.credential[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bIdObject {
    const MAX_BUFFER_SIZE: usize = TpmsIdObject::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.credential[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.credential[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bIdObject {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.credential, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bIdObject {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            credential: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bIdObject {
    type StructType = TpmsIdObject;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.credential[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bNvPublic
// ---------------------------------------------------------------------------
/// `TPM2B_NV_PUBLIC` structure defined in TPM 2.0 Part 2: Structures, Section 13.2 (Table 228).
///
/// A sized buffer wrapping `TPMS_NV_PUBLIC`, defining the public parameters of an NV Index
/// (index handle, name hash algorithm, attributes, policy, and data size).
#[doc(alias = "TPM2B_NV_PUBLIC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bNvPublic {
    pub(crate) size: u16,
    pub(crate) nv_public: [u8; TpmsNvPublic::MAX_SIZE],
}
impl Default for Tpm2bNvPublic {
    fn default() -> Self {
        Self {
            size: 0,
            nv_public: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bNvPublic {
    fn as_ref(&self) -> &[u8] {
        &self.nv_public[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bNvPublic {
    const MAX_BUFFER_SIZE: usize = TpmsNvPublic::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.nv_public[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.nv_public[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bNvPublic {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.nv_public, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bNvPublic {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            nv_public: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bNvPublic {
    type StructType = TpmsNvPublic;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.nv_public[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

// ---------------------------------------------------------------------------
// Tpm2bContextSensitive
// ---------------------------------------------------------------------------
/// `TPM2B_CONTEXT_SENSITIVE` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 232).
///
/// A sized buffer holding the encrypted sensitive portion of a saved object or session context.
#[doc(alias = "TPM2B_CONTEXT_SENSITIVE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bContextSensitive {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TPM2_MAX_CONTEXT_SIZE as usize],
}
impl Default for Tpm2bContextSensitive {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bContextSensitive {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bContextSensitive {
    const MAX_BUFFER_SIZE: usize = TPM2_MAX_CONTEXT_SIZE as usize;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bContextSensitive {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bContextSensitive {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ TPM2_MAX_CONTEXT_SIZE as usize }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bContextData
// ---------------------------------------------------------------------------
/// `TPM2B_CONTEXT_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 14.3 (Table 235).
///
/// A sized buffer wrapping `TPMS_CONTEXT_DATA`, holding integrity values and encrypted data for a saved context
/// in `TPM2_ContextSave` and `TPM2_ContextLoad`.
#[doc(alias = "TPM2B_CONTEXT_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bContextData {
    pub(crate) size: u16,
    pub(crate) buffer: [u8; TpmsContextData::MAX_SIZE],
}
impl Default for Tpm2bContextData {
    fn default() -> Self {
        Self {
            size: 0,
            buffer: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bContextData {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bContextData {
    const MAX_BUFFER_SIZE: usize = TpmsContextData::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.buffer[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.buffer[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bContextData {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.buffer, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bContextData {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self { size, buffer: buf })
    }
}

// ---------------------------------------------------------------------------
// Tpm2bCreationData
// ---------------------------------------------------------------------------
/// `TPM2B_CREATION_DATA` structure defined in TPM 2.0 Part 2: Structures, Section 15.1 (Table 239).
///
/// A sized buffer wrapping `TPMS_CREATION_DATA`, generated by the TPM upon object creation (`TPM2_Create`, `TPM2_CreatePrimary`)
/// to document the environment in which the object was created.
#[doc(alias = "TPM2B_CREATION_DATA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tpm2bCreationData {
    pub(crate) size: u16,
    pub(crate) creation_data: [u8; TpmsCreationData::MAX_SIZE],
}
impl Default for Tpm2bCreationData {
    fn default() -> Self {
        Self {
            size: 0,
            creation_data: [0; Self::MAX_BUFFER_SIZE],
        }
    }
}
impl AsRef<[u8]> for Tpm2bCreationData {
    fn as_ref(&self) -> &[u8] {
        &self.creation_data[..self.size as usize]
    }
}
impl Tpm2bSimple for Tpm2bCreationData {
    const MAX_BUFFER_SIZE: usize = TpmsCreationData::MAX_SIZE;
    fn get_size(&self) -> u16 {
        self.size
    }
    fn get_buffer(&self) -> &[u8] {
        &self.creation_data[..self.get_size() as usize]
    }
    fn from_bytes(buffer: &[u8]) -> Result<Self, UnmarshalError> {
        if buffer.len() > core::cmp::min(u16::MAX as usize, Self::MAX_BUFFER_SIZE) {
            return Err(UnmarshalError);
        }
        let mut dest = Self {
            size: buffer.len() as u16,
            ..Default::default()
        };
        dest.creation_data[..buffer.len()].copy_from_slice(buffer);
        Ok(dest)
    }
}
impl Marshal for Tpm2bCreationData {
    const MAX_SIZE: usize = u16::MAX_SIZE + Self::MAX_BUFFER_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_2b_simple(self.size, &self.creation_data, Self::MAX_BUFFER_SIZE, dst)
    }
}

impl<'a> Unmarshal<'a> for Tpm2bCreationData {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let (size, buf) = unmarshal_2b_simple::<{ Self::MAX_BUFFER_SIZE }>(src)?;
        Ok(Self {
            size,
            creation_data: buf,
        })
    }
}
impl Tpm2bStruct for Tpm2bCreationData {
    type StructType = TpmsCreationData;
    fn from_struct(val: &Self::StructType) -> Result<Self, UnmarshalError> {
        let mut x = Self::default();
        let mut max_buf = [0u8; Self::StructType::MAX_SIZE];
        let sz = val.marshal(&mut max_buf);
        if sz > Self::MAX_BUFFER_SIZE {
            return Err(UnmarshalError);
        }
        x.size = sz as u16;
        x.creation_data[..sz].copy_from_slice(&max_buf[..sz]);
        Ok(x)
    }
    fn to_struct(&self) -> Result<Self::StructType, UnmarshalError> {
        tpm2b_to_struct(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unmarshal_invalid_public_type() {
        let mut buf = [0u8; 12];
        buf[0] = 0x00;
        buf[1] = 10; // size of TpmtPublic
        buf[2] = 0x00;
        buf[3] = 0x00; // type = 0 (invalid)
        buf[4] = 0x00;
        buf[5] = 0x0B; // name_alg = SHA256
        // rest are 0 (attrs = 0, auth_policy size = 0)

        let mut slice: &[u8] = &buf;
        let res = Tpm2bPublic::unmarshal(&mut slice);
        assert_eq!(res.unwrap_err(), crate::errors::UnmarshalError);
    }
}
