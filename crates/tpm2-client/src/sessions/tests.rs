use tpm2::{Handle, Tpm2bSimple};

use super::*;

#[test]
fn test_password_auth_command() {
    let session = PasswordSession::new("hello").unwrap();
    let tpm_auth = session.auth_command();
    assert_eq!(tpm_auth.session_handle, Handle::RS_PW);
    assert_eq!(tpm_auth.hmac.get_size(), 5);
    assert_eq!(tpm_auth.hmac.get_buffer(), b"hello");
}
