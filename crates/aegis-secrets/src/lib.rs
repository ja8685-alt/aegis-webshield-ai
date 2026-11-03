use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[cfg(windows)]
mod windows_credential;

#[cfg(windows)]
pub use windows_credential::WindowsCredentialStore;

#[cfg(windows)]
pub type PlatformSecretStore = WindowsCredentialStore;

#[cfg(not(windows))]
pub type PlatformSecretStore = MemorySecretStore;

const MIN_SECRET_LEN: usize = 20;
const MAX_SECRET_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDescriptor {
    pub provider: String,
    pub account: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretSnapshot {
    pub provider: String,
    pub account: String,
    pub masked_value: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret provider is invalid")]
    InvalidProvider,
    #[error("secret account is invalid")]
    InvalidAccount,
    #[error("secret value is invalid")]
    InvalidSecretValue,
    #[error("secret was not found")]
    NotFound,
    #[error("secret store is unavailable")]
    StoreUnavailable,
}

pub trait SecretStore {
    fn save_secret(
        &self,
        descriptor: &SecretDescriptor,
        secret_value: &str,
    ) -> Result<SecretSnapshot, SecretError>;
    fn get_secret(&self, descriptor: &SecretDescriptor) -> Result<String, SecretError>;
    fn delete_secret(&self, descriptor: &SecretDescriptor) -> Result<(), SecretError>;
}

#[derive(Debug, Default, Clone)]
pub struct MemorySecretStore {
    values: Arc<Mutex<HashMap<String, String>>>,
}

impl SecretStore for MemorySecretStore {
    fn save_secret(
        &self,
        descriptor: &SecretDescriptor,
        secret_value: &str,
    ) -> Result<SecretSnapshot, SecretError> {
        validate_descriptor(descriptor)?;
        validate_secret_value(secret_value)?;
        let key = descriptor_key(descriptor);
        let mut values = self
            .values
            .lock()
            .map_err(|_| SecretError::StoreUnavailable)?;
        values.insert(key, secret_value.trim().to_string());
        Ok(SecretSnapshot {
            provider: descriptor.provider.trim().to_string(),
            account: descriptor.account.trim().to_string(),
            masked_value: mask_secret(secret_value),
        })
    }

    fn get_secret(&self, descriptor: &SecretDescriptor) -> Result<String, SecretError> {
        validate_descriptor(descriptor)?;
        let values = self
            .values
            .lock()
            .map_err(|_| SecretError::StoreUnavailable)?;
        values
            .get(&descriptor_key(descriptor))
            .cloned()
            .ok_or(SecretError::NotFound)
    }

    fn delete_secret(&self, descriptor: &SecretDescriptor) -> Result<(), SecretError> {
        validate_descriptor(descriptor)?;
        let mut values = self
            .values
            .lock()
            .map_err(|_| SecretError::StoreUnavailable)?;
        values.remove(&descriptor_key(descriptor));
        Ok(())
    }
}

pub fn mask_secret(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 8 {
        return "********".to_string();
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}

pub fn validate_descriptor(descriptor: &SecretDescriptor) -> Result<(), SecretError> {
    let provider = descriptor.provider.trim();
    let account = descriptor.account.trim();
    if provider.is_empty()
        || provider.len() > 80
        || !provider
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(SecretError::InvalidProvider);
    }
    if account.is_empty() || account.len() > 160 || account.contains(char::is_whitespace) {
        return Err(SecretError::InvalidAccount);
    }
    Ok(())
}

pub fn validate_secret_value(value: &str) -> Result<(), SecretError> {
    let value = value.trim();
    if value.len() < MIN_SECRET_LEN || value.len() > MAX_SECRET_LEN || value.contains('\0') {
        return Err(SecretError::InvalidSecretValue);
    }
    Ok(())
}

fn descriptor_key(descriptor: &SecretDescriptor) -> String {
    format!(
        "{}:{}",
        descriptor.provider.trim().to_ascii_lowercase(),
        descriptor.account.trim().to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> SecretDescriptor {
        SecretDescriptor {
            provider: "openai".to_string(),
            account: "local-user".to_string(),
        }
    }

    #[test]
    fn saves_and_masks_secret_without_exposing_plaintext() {
        let store = MemorySecretStore::default();
        let snapshot = store
            .save_secret(&descriptor(), "sk-test-1234567890abcdef")
            .expect("secret saved");

        assert_eq!(snapshot.masked_value, "sk-t...cdef");
        assert_eq!(
            store.get_secret(&descriptor()).expect("secret loaded"),
            "sk-test-1234567890abcdef"
        );
    }

    #[test]
    fn rejects_short_secret() {
        let store = MemorySecretStore::default();
        let error = store
            .save_secret(&descriptor(), "short")
            .expect_err("short secret rejected");

        assert_eq!(error, SecretError::InvalidSecretValue);
    }

    #[test]
    fn rejects_provider_with_spaces() {
        let descriptor = SecretDescriptor {
            provider: "bad provider".to_string(),
            account: "local-user".to_string(),
        };

        assert_eq!(
            validate_descriptor(&descriptor),
            Err(SecretError::InvalidProvider)
        );
    }

    #[test]
    fn deletes_secret() {
        let store = MemorySecretStore::default();
        store
            .save_secret(&descriptor(), "sk-test-1234567890abcdef")
            .expect("secret saved");

        store.delete_secret(&descriptor()).expect("secret deleted");

        assert_eq!(store.get_secret(&descriptor()), Err(SecretError::NotFound));
    }
}
