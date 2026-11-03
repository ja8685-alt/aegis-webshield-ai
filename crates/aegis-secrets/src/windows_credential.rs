use crate::{
    mask_secret, validate_descriptor, validate_secret_value, SecretDescriptor, SecretError,
    SecretSnapshot, SecretStore,
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::slice;
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsCredentialStore;

impl SecretStore for WindowsCredentialStore {
    fn save_secret(
        &self,
        descriptor: &SecretDescriptor,
        secret_value: &str,
    ) -> Result<SecretSnapshot, SecretError> {
        validate_descriptor(descriptor)?;
        validate_secret_value(secret_value)?;

        let mut target_name = wide_null(&credential_target_name(descriptor));
        let mut user_name = wide_null(descriptor.account.trim());
        let mut secret_bytes = secret_value.trim().as_bytes().to_vec();
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_name.as_mut_ptr(),
            Comment: null_mut(),
            LastWritten: Default::default(),
            CredentialBlobSize: secret_bytes.len() as u32,
            CredentialBlob: secret_bytes.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: null_mut(),
            TargetAlias: null_mut(),
            UserName: user_name.as_mut_ptr(),
        };

        let written = unsafe { CredWriteW(&credential, 0) };
        if written == 0 {
            return Err(SecretError::StoreUnavailable);
        }

        Ok(SecretSnapshot {
            provider: descriptor.provider.trim().to_string(),
            account: descriptor.account.trim().to_string(),
            masked_value: mask_secret(secret_value),
        })
    }

    fn get_secret(&self, descriptor: &SecretDescriptor) -> Result<String, SecretError> {
        validate_descriptor(descriptor)?;
        let target_name = wide_null(&credential_target_name(descriptor));
        let mut credential_ptr = null_mut();
        let read = unsafe {
            CredReadW(
                target_name.as_ptr(),
                CRED_TYPE_GENERIC,
                0,
                &mut credential_ptr,
            )
        };
        if read == 0 {
            return Err(SecretError::NotFound);
        }
        if credential_ptr.is_null() {
            return Err(SecretError::StoreUnavailable);
        }

        let result = unsafe {
            let credential = &*credential_ptr;
            let bytes = slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            );
            let value =
                String::from_utf8(bytes.to_vec()).map_err(|_| SecretError::StoreUnavailable);
            CredFree(credential_ptr.cast());
            value
        }?;
        Ok(result)
    }

    fn delete_secret(&self, descriptor: &SecretDescriptor) -> Result<(), SecretError> {
        validate_descriptor(descriptor)?;
        let target_name = wide_null(&credential_target_name(descriptor));
        let deleted = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if deleted == 0 {
            return Err(SecretError::NotFound);
        }
        Ok(())
    }
}

fn credential_target_name(descriptor: &SecretDescriptor) -> String {
    format!(
        "AegisWebShieldAI:{}:{}",
        descriptor.provider.trim().to_ascii_lowercase(),
        descriptor.account.trim().to_ascii_lowercase()
    )
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain([0]).collect()
}
