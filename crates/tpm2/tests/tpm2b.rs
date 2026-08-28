use tpm2::*;

macro_rules! impl_test_tpm2b_simple {
    ($T:ty) => {
        const SIZE_OF_U16: usize = u16::MAX_SIZE;
        const SIZE_OF_TYPE: usize = <$T>::MAX_SIZE;

        /*
         * Generate arrays that are:
         *   - too small
         *   - smaller than buffer limit
         *   - same size as buffer limit
         *   - exceeding buffer limit
         */
        let too_small_size_buf: [u8; 1] = [0x00; 1];
        let mut smaller_size_buf: [u8; SIZE_OF_TYPE - 8] = [0xFF; SIZE_OF_TYPE - 8];
        let mut same_size_buf: [u8; SIZE_OF_TYPE] = [0xFF; SIZE_OF_TYPE];
        let mut bigger_size_buf: [u8; SIZE_OF_TYPE + 8] = [0xFF; SIZE_OF_TYPE + 8];

        let mut s = (smaller_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut smaller_size_buf[0..2]).try_into().unwrap());

        s = (same_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut same_size_buf[0..2]).try_into().unwrap());

        s = (bigger_size_buf.len() - SIZE_OF_U16) as u16;
        s.marshal((&mut bigger_size_buf[0..2]).try_into().unwrap());

        // too small should fail
        let mut slice = &too_small_size_buf[..];
        let mut result: Result<$T, tpm2::errors::UnmarshalError> = <$T>::unmarshal(&mut slice);
        assert!(result.is_err());

        // bigger size should consume only the prefix
        let mut slice = &bigger_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_err());

        // small, should be good
        let mut slice = &smaller_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_ok());
        let digest = result.unwrap();
        assert_eq!(
            usize::from(digest.get_size()),
            smaller_size_buf.len() - SIZE_OF_U16
        );
        assert_eq!(digest.get_buffer(), &smaller_size_buf[SIZE_OF_U16..]);

        // same size should be good
        let mut slice = &same_size_buf[..];
        result = <$T>::unmarshal(&mut slice);
        assert!(result.is_ok());
        let digest = result.unwrap();
        assert_eq!(
            usize::from(digest.get_size()),
            same_size_buf.len() - SIZE_OF_U16
        );
        assert_eq!(digest.get_buffer(), &same_size_buf[SIZE_OF_U16..]);

        let mut mbuf = [0u8; <$T>::MAX_SIZE];
        let mres = digest.marshal(&mut mbuf);
        assert_eq!(mres, digest.get_size() as usize + SIZE_OF_U16);
        let mut slice = &mbuf[..mres];
        let new_digest = <$T>::unmarshal(&mut slice).unwrap();
        assert_eq!(digest, new_digest);
    };
}

#[test]
fn test_try_unmarshal_tpm2b_name() {
    impl_test_tpm2b_simple! {Tpm2bName};
}

#[test]
fn test_try_unmarshal_tpm2b_attest() {
    impl_test_tpm2b_simple! {Tpm2bAttest};
}

#[test]
fn test_try_unmarshal_tpm2b_context_data() {
    impl_test_tpm2b_simple! {Tpm2bContextData};
}

#[test]
fn test_try_unmarshal_tpm2b_context_sensitive() {
    impl_test_tpm2b_simple! {Tpm2bContextSensitive};
}

#[test]
fn test_try_unmarshal_tpm2b_data() {
    impl_test_tpm2b_simple! {Tpm2bData};
}

#[test]
fn test_try_unmarshal_tpm2b_digest() {
    impl_test_tpm2b_simple! {Tpm2bDigest};
}

#[test]
fn test_try_unmarshal_tpm2b_ecc_parameter() {
    impl_test_tpm2b_simple! {Tpm2bEccParameter};
}

#[test]
fn test_try_unmarshal_tpm2b_encrypted_secret() {
    impl_test_tpm2b_simple! {Tpm2bEncryptedSecret};
}

#[test]
fn test_try_unmarshal_tpm2b_event() {
    impl_test_tpm2b_simple! {Tpm2bEvent};
}

#[test]
fn test_try_unmarshal_tpm2b_id_object() {
    impl_test_tpm2b_simple! {Tpm2bIdObject};
}

#[test]
fn test_try_unmarshal_tpm2b_iv() {
    impl_test_tpm2b_simple! {Tpm2bIv};
}

#[test]
fn test_try_unmarshal_tpm2b_max_buffer() {
    impl_test_tpm2b_simple! {Tpm2bMaxBuffer};
}

#[test]
fn test_try_unmarshal_tpm2b_max_nv_buffer() {
    impl_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
}

#[test]
fn test_try_unmarshal_tpm2b_private() {
    impl_test_tpm2b_simple! {Tpm2bPrivate};
}

#[test]
fn test_try_unmarshal_tpm2b_private_key_rsa() {
    impl_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
}

#[test]
fn test_try_unmarshal_tpm2b_public_key_rsa() {
    impl_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
}

#[test]
fn test_try_unmarshal_tpm2b_sensitive_data() {
    impl_test_tpm2b_simple! {Tpm2bSensitiveData};
}

#[test]
fn test_try_unmarshal_tpm2b_sensitive() {
    impl_test_tpm2b_simple! {Tpm2bSensitive};
}

#[test]
fn test_try_unmarshal_tpm2b_sym_key() {
    impl_test_tpm2b_simple! {Tpm2bSymKey};
}

#[test]
fn test_try_unmarshal_tpm2b_template() {
    impl_test_tpm2b_simple! {Tpm2bTemplate};
}

macro_rules! impl_stress_test_tpm2b_simple {
    ($T:ty) => {
        let max_size = <$T>::MAX_BUFFER_SIZE;
        let test_sizes = [0, 1, 2, max_size / 2, max_size];
        for &size in &test_sizes {
            if size > max_size {
                continue;
            }
            let bytes = vec![0u8; size];
            let struct_val = <$T>::from_bytes(&bytes).unwrap();
            let expected_marshaled_len = 2 + size;

            let mut mbuf = [0u8; <$T>::MAX_SIZE];
            let res = struct_val.marshal(&mut mbuf);
            assert_eq!(res, expected_marshaled_len);
            let mut slice = &mbuf[..res];
            let unmarshaled = <$T>::unmarshal(&mut slice).unwrap();
            assert_eq!(struct_val, unmarshaled);
        }
    };
}

#[test]
fn test_all_tpm2b_simple_marshalling_bounds() {
    impl_stress_test_tpm2b_simple! {Tpm2bName};
    impl_stress_test_tpm2b_simple! {Tpm2bAttest};
    impl_stress_test_tpm2b_simple! {Tpm2bContextData};
    impl_stress_test_tpm2b_simple! {Tpm2bContextSensitive};
    impl_stress_test_tpm2b_simple! {Tpm2bData};
    impl_stress_test_tpm2b_simple! {Tpm2bDigest};
    impl_stress_test_tpm2b_simple! {Tpm2bEccParameter};
    impl_stress_test_tpm2b_simple! {Tpm2bEncryptedSecret};
    impl_stress_test_tpm2b_simple! {Tpm2bEvent};
    impl_stress_test_tpm2b_simple! {Tpm2bIdObject};
    impl_stress_test_tpm2b_simple! {Tpm2bIv};
    impl_stress_test_tpm2b_simple! {Tpm2bMaxBuffer};
    impl_stress_test_tpm2b_simple! {Tpm2bMaxNvBuffer};
    impl_stress_test_tpm2b_simple! {Tpm2bPrivate};
    impl_stress_test_tpm2b_simple! {Tpm2bPrivateKeyRsa};
    impl_stress_test_tpm2b_simple! {Tpm2bPublicKeyRsa};
    impl_stress_test_tpm2b_simple! {Tpm2bSensitiveData};
    impl_stress_test_tpm2b_simple! {Tpm2bSensitive};
    impl_stress_test_tpm2b_simple! {Tpm2bSymKey};
    impl_stress_test_tpm2b_simple! {Tpm2bTemplate};
}
