use crate::{
    errors::{TpmRc, UnmarshalError},
    marshal::marshal_helper,
    *,
};

pub const TPM2_MAX_CAP_DATA: usize =
    TPM2_MAX_CAP_BUFFER as usize - TpmCap::MAX_SIZE - u32::MAX_SIZE;
pub const TPM2_MAX_CAP_ALGS: usize = TPM2_MAX_CAP_DATA / TpmsAlgProperty::MAX_SIZE;
pub const TPM2_MAX_CAP_HANDLES: usize = TPM2_MAX_CAP_DATA / Handle::MAX_SIZE;
pub const TPM2_MAX_CAP_CC: usize = TPM2_MAX_CAP_DATA / TpmCc::MAX_SIZE;
pub const TPM2_MAX_TPM_PROPERTIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedProperty::MAX_SIZE;
pub const TPM2_MAX_PCR_PROPERTIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedPcrSelect::MAX_SIZE;
pub const TPM2_MAX_ECC_CURVES: usize = TPM2_MAX_CAP_DATA / TpmEccCurve::MAX_SIZE;
pub const TPM2_MAX_TAGGED_POLICIES: usize = TPM2_MAX_CAP_DATA / TpmsTaggedPolicy::MAX_SIZE;
pub const TPM2_MAX_ALG_LIST_SIZE: usize = 64;

fn unmarshal_tpml_elements<'a, T: Unmarshal<'a> + Default + Copy, const N: usize>(
    src: &mut &'a [u8],
    count: u32,
) -> Result<[T; N], UnmarshalError> {
    if count as usize > N {
        return Err(UnmarshalError);
    }
    let mut list = [T::default(); N];
    for elem in list.iter_mut().take(count as usize) {
        *elem = Unmarshal::unmarshal(src)?;
    }
    Ok(list)
}

fn marshal_tpml_elements<T: Marshal<MaxBuffer = [u8; M]>, const M: usize, const N: usize>(
    count: u32,
    elements: &[T; N],
    dst: &mut [u8],
) -> usize {
    let mut written = marshal_helper(&count, dst, 0);
    for elem in elements.iter().take(count as usize) {
        written = marshal_helper(elem, dst, written);
    }
    written
}

/// `TPML_PCR_SELECTION` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.8 (Table 127).
///
/// Holds a count and an array of PCR selection structures (`TPMS_PCR_SELECTION`), representing PCR selections across multiple hash banks.
/// Used in commands such as `TPM2_PCR_Read`, `TPM2_PolicyPCR`, and `TPM2_Quote`.
#[doc(alias = "TPML_PCR_SELECTION")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlPcrSelection {
    pub(crate) count: u32,
    /// List of PCR selections.
    pub(crate) pcr_selections: [Option<TpmsPcrSelection>; TpmtHa::HASH_COUNT],
}

impl Default for TpmlPcrSelection {
    fn default() -> Self {
        Self {
            count: 0,
            pcr_selections: [None; _],
        }
    }
}

impl Marshal for TpmlPcrSelection {
    const MAX_SIZE: usize = u32::MAX_SIZE + TpmtHa::HASH_COUNT * TpmsPcrSelection::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = marshal_helper(&self.count, dst, 0);
        for p in self.pcr_selections() {
            offset = marshal_helper(p, dst, offset);
        }
        offset
    }
}

impl<'a> Unmarshal<'a> for TpmlPcrSelection {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        if count as usize > TpmtHa::HASH_COUNT {
            return Err(UnmarshalError);
        }
        let mut pcr_selections = [None; _];
        for elem in pcr_selections.iter_mut().take(count as usize) {
            *elem = Some(TpmsPcrSelection::unmarshal(src)?);
        }
        Ok(Self {
            count,
            pcr_selections,
        })
    }
}

impl TpmlPcrSelection {
    pub fn new(elements: &[TpmsPcrSelection]) -> Result<Self, TpmRc> {
        if elements.len() > TpmtHa::HASH_COUNT {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut pcr_selections = [None; _];
        for (i, elem) in elements.iter().enumerate() {
            pcr_selections[i] = Some(*elem);
        }
        Ok(Self {
            count: elements.len() as u32,
            pcr_selections,
        })
    }

    pub fn add(&mut self, element: &TpmsPcrSelection) -> Result<(), TpmRc> {
        if self.count() >= self.pcr_selections.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        self.pcr_selections[self.count()] = Some(*element);
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn pcr_selections(&self) -> impl Iterator<Item = &TpmsPcrSelection> {
        self.pcr_selections[..self.count()]
            .iter()
            .filter_map(|p| p.as_ref())
    }

    pub fn get(&self, index: usize) -> Option<&TpmsPcrSelection> {
        if index < self.count() {
            self.pcr_selections[index].as_ref()
        } else {
            None
        }
    }
}

impl core::ops::Index<usize> for TpmlPcrSelection {
    type Output = TpmsPcrSelection;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

/// `TPML_ALG_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.9 (Table 128).
///
/// Holds a count and an array of algorithm properties (`TPMS_ALG_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ALGS)`.
#[doc(alias = "TPML_ALG_PROPERTY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlAlgProperty {
    pub(crate) count: u32,
    pub(crate) alg_properties: [TpmsAlgProperty; TPM2_MAX_CAP_ALGS],
}

impl Marshal for TpmlAlgProperty {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_CAP_ALGS * TpmsAlgProperty::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.alg_properties, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlAlgProperty {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let alg_properties = unmarshal_tpml_elements(src, count)?;
        Ok(Self {
            count,
            alg_properties,
        })
    }
}

/// `TPML_ALG` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.4 (Table 123).
///
/// Holds a count and an array of algorithm identifiers (`TPM_ALG_ID`).
/// Used in capability reporting and parameter validation.
#[doc(alias = "TPML_ALG")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlAlg {
    pub count: u32,
    pub algorithms: [Alg; TPM2_MAX_ALG_LIST_SIZE],
}

impl Marshal for TpmlAlg {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_ALG_LIST_SIZE * Alg::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.algorithms, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlAlg {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let algorithms = unmarshal_tpml_elements(src, count)?;
        Ok(Self { count, algorithms })
    }
}

/// `TPML_HANDLE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.5 (Table 124).
///
/// Holds a count and an array of TPM handle values (`TPM_HANDLE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_HANDLES)`.
#[doc(alias = "TPML_HANDLE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlHandle {
    pub(crate) count: u32,
    pub(crate) handle: [Handle; TPM2_MAX_CAP_HANDLES],
}

impl Marshal for TpmlHandle {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_CAP_HANDLES * Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.handle, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlHandle {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let handle = unmarshal_tpml_elements(src, count)?;
        Ok(Self { count, handle })
    }
}

/// `TPML_CCA` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.3 (Table 122).
///
/// Holds a count and an array of command attributes (`TPMA_CC`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_COMMANDS)`.
#[doc(alias = "TPML_CCA")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlCca {
    pub(crate) count: u32,
    pub(crate) command_attributes: [TpmaCc; TPM2_MAX_CAP_CC],
}

impl Marshal for TpmlCca {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_CAP_CC * TpmaCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.command_attributes, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlCca {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let command_attributes = unmarshal_tpml_elements(src, count)?;
        Ok(Self {
            count,
            command_attributes,
        })
    }
}

/// `TPML_CC` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.2 (Table 121).
///
/// Holds a count and an array of command codes (`TPM_CC`).
/// Used in capability reporting and command audit settings.
#[doc(alias = "TPML_CC")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlCc {
    pub(crate) count: u32,
    pub(crate) command_codes: [TpmCc; TPM2_MAX_CAP_CC],
}

impl Marshal for TpmlCc {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_CAP_CC * TpmCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.command_codes, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlCc {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let command_codes = unmarshal_tpml_elements(src, count)?;
        Ok(Self {
            count,
            command_codes,
        })
    }
}

/// `TPML_TAGGED_TPM_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.10 (Table 129).
///
/// Holds a count and an array of tagged TPM property structures (`TPMS_TAGGED_PROPERTY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`.
#[doc(alias = "TPML_TAGGED_TPM_PROPERTY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlTaggedTpmProperty {
    pub count: u32,
    pub tpm_property: [TpmsTaggedProperty; TPM2_MAX_TPM_PROPERTIES],
}

impl Marshal for TpmlTaggedTpmProperty {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_TPM_PROPERTIES * TpmsTaggedProperty::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.tpm_property, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlTaggedTpmProperty {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let tpm_property = unmarshal_tpml_elements(src, count)?;
        Ok(Self {
            count,
            tpm_property,
        })
    }
}

/// `TPML_TAGGED_PCR_PROPERTY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.11 (Table 130).
///
/// Holds a count and an array of tagged PCR property structures (`TPMS_TAGGED_PCR_SELECT`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_PCRS)`.
#[doc(alias = "TPML_TAGGED_PCR_PROPERTY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlTaggedPcrProperty {
    pub count: u32,
    pub pcr_property: [TpmsTaggedPcrSelect; TPM2_MAX_PCR_PROPERTIES],
}

impl Marshal for TpmlTaggedPcrProperty {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_PCR_PROPERTIES * TpmsTaggedPcrSelect::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.pcr_property, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlTaggedPcrProperty {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let pcr_property = unmarshal_tpml_elements(src, count)?;
        Ok(Self {
            count,
            pcr_property,
        })
    }
}

/// `TPML_ECC_CURVE` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.12 (Table 131).
///
/// Holds a count and an array of ECC curve identifiers (`TPM_ECC_CURVE`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ECC_CURVES)`.
#[doc(alias = "TPML_ECC_CURVE")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlEccCurve {
    pub(crate) count: u32,
    pub(crate) ecc_curves: [Option<TpmEccCurve>; TPM2_MAX_ECC_CURVES],
}

impl Default for TpmlEccCurve {
    fn default() -> Self {
        Self {
            count: 0,
            ecc_curves: [None; TPM2_MAX_ECC_CURVES],
        }
    }
}

impl Marshal for TpmlEccCurve {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_ECC_CURVES * TpmEccCurve::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = marshal_helper(&self.count, dst, 0);
        for c in self.ecc_curves() {
            offset = marshal_helper(c, dst, offset);
        }
        offset
    }
}

impl<'a> Unmarshal<'a> for TpmlEccCurve {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        if count as usize > TPM2_MAX_ECC_CURVES {
            return Err(UnmarshalError);
        }
        let mut ecc_curves = [None; TPM2_MAX_ECC_CURVES];
        for elem in ecc_curves.iter_mut().take(count as usize) {
            *elem = Some(TpmEccCurve::unmarshal(src)?);
        }
        Ok(Self { count, ecc_curves })
    }
}

impl TpmlEccCurve {
    pub fn new(elements: &[TpmEccCurve]) -> Result<Self, TpmRc> {
        if elements.len() > TPM2_MAX_ECC_CURVES {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut ecc_curves = [None; TPM2_MAX_ECC_CURVES];
        for (i, elem) in elements.iter().enumerate() {
            ecc_curves[i] = Some(*elem);
        }
        Ok(Self {
            count: elements.len() as u32,
            ecc_curves,
        })
    }

    pub fn add(&mut self, element: &TpmEccCurve) -> Result<(), TpmRc> {
        if self.count() >= self.ecc_curves.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        self.ecc_curves[self.count()] = Some(*element);
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn ecc_curves(&self) -> impl Iterator<Item = &TpmEccCurve> {
        self.ecc_curves[..self.count()]
            .iter()
            .filter_map(|c| c.as_ref())
    }

    pub fn get(&self, index: usize) -> Option<&TpmEccCurve> {
        if index < self.count() {
            self.ecc_curves[index].as_ref()
        } else {
            None
        }
    }
}

impl core::ops::Index<usize> for TpmlEccCurve {
    type Output = TpmEccCurve;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

/// `TPML_TAGGED_POLICY` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.13 (Table 132).
///
/// Holds a count and an array of tagged policy structures (`TPMS_TAGGED_POLICY`).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_POLICIES)`.
#[doc(alias = "TPML_TAGGED_POLICY")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlTaggedPolicy<'a> {
    pub(crate) count: u32,
    pub(crate) policies: [Option<TpmsTaggedPolicy<'a>>; TPM2_MAX_TAGGED_POLICIES],
}

impl<'a> Default for TpmlTaggedPolicy<'a> {
    fn default() -> Self {
        Self {
            count: 0,
            policies: [None; TPM2_MAX_TAGGED_POLICIES],
        }
    }
}

impl<'a> Marshal for TpmlTaggedPolicy<'a> {
    const MAX_SIZE: usize = u32::MAX_SIZE + TPM2_MAX_TAGGED_POLICIES * TpmsTaggedPolicy::MAX_SIZE;
    type MaxBuffer = [u8; TpmlTaggedPolicy::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = marshal_helper(&self.count, dst, 0);
        for p in self.policies() {
            offset = marshal_helper(p, dst, offset);
        }
        offset
    }
}

impl<'a> Unmarshal<'a> for TpmlTaggedPolicy<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        if count as usize > TPM2_MAX_TAGGED_POLICIES {
            return Err(UnmarshalError);
        }
        let mut policies = [None; TPM2_MAX_TAGGED_POLICIES];
        for elem in policies.iter_mut().take(count as usize) {
            *elem = Some(TpmsTaggedPolicy::unmarshal(src)?);
        }
        Ok(Self { count, policies })
    }
}

impl<'a> TpmlTaggedPolicy<'a> {
    pub fn new(elements: &[TpmsTaggedPolicy<'a>]) -> Result<Self, TpmRc> {
        if elements.len() > TPM2_MAX_TAGGED_POLICIES {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut policies = [None; TPM2_MAX_TAGGED_POLICIES];
        for (i, elem) in elements.iter().enumerate() {
            policies[i] = Some(*elem);
        }
        Ok(Self {
            count: elements.len() as u32,
            policies,
        })
    }

    pub fn add(&mut self, element: &TpmsTaggedPolicy<'a>) -> Result<(), TpmRc> {
        if self.count() >= self.policies.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        self.policies[self.count()] = Some(*element);
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn policies(&self) -> impl Iterator<Item = &TpmsTaggedPolicy<'a>> {
        self.policies[..self.count()]
            .iter()
            .filter_map(|p| p.as_ref())
    }

    pub fn get(&self, index: usize) -> Option<&TpmsTaggedPolicy<'a>> {
        if index < self.count() {
            self.policies[index].as_ref()
        } else {
            None
        }
    }
}

impl<'a> core::ops::Index<usize> for TpmlTaggedPolicy<'a> {
    type Output = TpmsTaggedPolicy<'a>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

/// `TPML_DIGEST` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.6 (Table 125).
///
/// Holds a count and an array of digest values (`TPM2B_DIGEST`).
/// Used in commands such as `TPM2_PolicyOR` to provide a list of expected policy hashes.
#[doc(alias = "TPML_DIGEST")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlDigest {
    pub(crate) count: u32,
    pub(crate) digests: [Tpm2bDigest; 8],
}

impl Marshal for TpmlDigest {
    const MAX_SIZE: usize = u32::MAX_SIZE + 8 * Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        marshal_tpml_elements(self.count, &self.digests, dst)
    }
}

impl<'a> Unmarshal<'a> for TpmlDigest {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        let digests = unmarshal_tpml_elements(src, count)?;
        Ok(Self { count, digests })
    }
}

/// `TPML_DIGEST_VALUES` structure defined in TPM 2.0 Part 2: Structures, Section 10.5.7 (Table 126).
///
/// Holds a count and an array of tagged digest values (`TPMT_HA`).
/// Used in `TPM2_PCR_Extend` and `TPM2_EventSequenceComplete` to pass digests for multiple hash algorithms simultaneously.
#[doc(alias = "TPML_DIGEST_VALUES")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TpmlDigestValues<'a> {
    pub(crate) count: u32,
    pub(crate) digests: [Option<TpmtHa<'a>>; TpmtHa::HASH_COUNT],
}

impl<'a> Default for TpmlDigestValues<'a> {
    fn default() -> Self {
        Self {
            count: 0,
            digests: [None; _],
        }
    }
}

impl<'a> Marshal for TpmlDigestValues<'a> {
    const MAX_SIZE: usize = u32::MAX_SIZE + TpmtHa::HASH_COUNT * TpmtHa::MAX_SIZE;
    type MaxBuffer = [u8; TpmlDigestValues::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = marshal_helper(&self.count, dst, 0);
        for d in self.digests() {
            offset = marshal_helper(d, dst, offset);
        }
        offset
    }
}

impl<'a> Unmarshal<'a> for TpmlDigestValues<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let count = Unmarshal::unmarshal(src)?;
        if count as usize > TpmtHa::HASH_COUNT {
            return Err(UnmarshalError);
        }
        let mut digests = [None; TpmtHa::HASH_COUNT];
        for d in digests.iter_mut().take(count as usize) {
            *d = Some(TpmtHa::unmarshal(src)?);
        }
        Ok(Self { count, digests })
    }
}

impl<'a> TpmlDigestValues<'a> {
    pub fn new(elements: &[TpmtHa<'a>]) -> Result<Self, TpmRc> {
        if elements.len() > TpmtHa::HASH_COUNT {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut digests = [None; TpmtHa::HASH_COUNT];
        for (i, elem) in elements.iter().enumerate() {
            digests[i] = Some(*elem);
        }
        Ok(Self {
            count: elements.len() as u32,
            digests,
        })
    }

    pub fn add(&mut self, element: &TpmtHa<'a>) -> Result<(), TpmRc> {
        if self.count() >= self.digests.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        self.digests[self.count()] = Some(*element);
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }

    pub fn digests(&self) -> impl Iterator<Item = &TpmtHa<'a>> {
        self.digests[..self.count()]
            .iter()
            .filter_map(|d| d.as_ref())
    }

    pub fn get(&self, index: usize) -> Option<&TpmtHa<'a>> {
        if index < self.count() {
            self.digests[index].as_ref()
        } else {
            None
        }
    }
}

impl<'a> core::ops::Index<usize> for TpmlDigestValues<'a> {
    type Output = TpmtHa<'a>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

// Adds common helpers for TPML type $T.
macro_rules! impl_tpml {
    ($T:ty,  $ListField:ident, $ListType:ty) => {
        // Implement Default for the type. This cannot usually be derived, because $ListCapacity is too large.
        impl Default for $T {
            fn default() -> Self {
                Self {
                    count: 0,
                    $ListField: [<$ListType>::default(); _],
                }
            }
        }

        impl $T {
            pub fn new(elements: &[$ListType]) -> Result<$T, TpmRc> {
                let mut x = Self::default();
                if elements.len() > x.$ListField.len() {
                    // TODO: Should this return error in server or client value space?
                    return Err(TpmRc::SIZE.to_rc());
                }
                x.count = elements.len() as u32;
                x.$ListField[..elements.len()].copy_from_slice(elements);
                Ok(x)
            }

            pub fn add(&mut self, element: &$ListType) -> Result<(), TpmRc> {
                if self.count() >= self.$ListField.len() {
                    // TODO: Should this return error in server or client value space?
                    return Err(TpmRc::SIZE.to_rc());
                }
                self.$ListField[self.count()] = *element;
                self.count += 1;
                Ok(())
            }

            pub fn count(&self) -> usize {
                self.count as usize
            }

            pub fn $ListField(&self) -> &[$ListType] {
                &self.$ListField[..self.count()]
            }
        }
    };
}
impl_tpml! {TpmlAlgProperty, alg_properties, TpmsAlgProperty}
impl_tpml! {TpmlHandle, handle, Handle}
impl_tpml! {TpmlCc, command_codes, TpmCc}
impl_tpml! {TpmlCca, command_attributes, TpmaCc}
impl_tpml! {TpmlTaggedTpmProperty, tpm_property, TpmsTaggedProperty}
impl_tpml! {TpmlTaggedPcrProperty, pcr_property, TpmsTaggedPcrSelect}
impl_tpml! {TpmlDigest, digests, Tpm2bDigest}
impl_tpml! {TpmlAlg, algorithms, Alg}
