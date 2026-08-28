use tpm2::*;

#[test]
fn test_impl_tpml_new() {
    let elements: Vec<Handle> = (0..TPM2_MAX_CAP_HANDLES + 1)
        .map(|i| Handle(i as u32))
        .collect();
    for x in 0..TPM2_MAX_CAP_HANDLES {
        let slice = &elements.as_slice()[..x];
        let list = TpmlHandle::new(slice).unwrap();
        assert_eq!(list.count(), x);
        assert_eq!(list.handle(), slice);
    }
    assert!(
        TpmlHandle::new(elements.as_slice()).is_err(),
        "Creating a TpmlHandle with more elements than capacity should fail."
    );
}

#[test]
fn test_impl_tpml_default_add() {
    let elements: Vec<Handle> = (0..TPM2_MAX_CAP_HANDLES + 1)
        .map(|i| Handle(i as u32))
        .collect();
    let mut list = TpmlHandle::default();
    for x in 0..TPM2_MAX_CAP_HANDLES {
        let slice = &elements.as_slice()[..x];
        assert_eq!(list.handle(), slice);

        list.add(elements.get(x).unwrap()).unwrap();
        assert_eq!(list.count(), x + 1);
    }
    assert!(
        TpmlHandle::new(elements.as_slice()).is_err(),
        "Creating a TpmlHandle with more elements than capacity should fail."
    );
}
