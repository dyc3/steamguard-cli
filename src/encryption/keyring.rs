use keyring::Entry;

const KEYRING_SERVICE: &str = "steamguard-cli";

pub fn init_keyring(keyring_id: String) -> keyring::Result<Entry> {
	Entry::new(KEYRING_SERVICE, &keyring_id)
}
