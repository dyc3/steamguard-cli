use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};

const KEYRING_SERVICE: &str = "steamguard-cli";

pub fn init_keyring(keyring_id: String) -> keyring::Result<Entry> {
	Entry::new(KEYRING_SERVICE, &keyring_id)
}

pub fn try_passkey_from_keyring(keyring_id: String) -> keyring::Result<Option<SecretString>> {
	let entry = init_keyring(keyring_id)?;
	let passkey = entry.get_password()?;
	Ok(Some(SecretString::new(passkey)))
}

pub fn store_passkey(keyring_id: String, passkey: SecretString) -> keyring::Result<()> {
	let entry = init_keyring(keyring_id)?;
	entry.set_password(passkey.expose_secret())
}

pub fn clear_passkey(keyring_id: String) -> keyring::Result<()> {
	let entry = init_keyring(keyring_id)?;
	entry.delete_password()
}
