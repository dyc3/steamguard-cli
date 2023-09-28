use log::*;
use secrecy::ExposeSecret;

use crate::{
	encryption::{EncryptionScheme, EntryEncryptor},
	tui, AccountManager,
};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Encrypt all maFiles")]
pub struct EncryptCommand;

impl<T> ManifestCommand<T> for EncryptCommand
where
	T: Transport,
{
	fn execute(
		&self,
		_transport: T,
		manager: &mut AccountManager,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		if !manager.has_passkey() {
			let passkey: Option<SecretString>;
			loop {
				let passkey1 = tui::prompt_passkey()?;
				if passkey1.expose_secret().is_empty() {
					error!("Passkey cannot be empty, try again.");
					continue;
				}
				let passkey_confirm = rpassword::prompt_password("Confirm encryption passkey: ")
					.map(SecretString::new)?;
				if passkey1.expose_secret() == passkey_confirm.expose_secret() {
					passkey = Some(passkey1);
					break;
				}
				error!("Passkeys do not match, try again.");
			}

			#[cfg(feature = "keyring")]
			{
				if tui::prompt_char(
					"Would you like to store the passkey in your system keyring?",
					"yn",
				) == 'y'
				{
					let keyring_id = crate::encryption::generate_keyring_id();
					match crate::encryption::store_passkey(
						keyring_id.clone(),
						passkey.clone().unwrap(),
					) {
						Ok(_) => {
							info!("Stored passkey in keyring");
							manager.set_keyring_id(keyring_id);
						}
						Err(e) => warn!(
							"Failed to store passkey in keyring, continuing anyway: {}",
							e
						),
					}
				}
			}

			manager.submit_passkey(passkey);
		}
		manager.load_accounts()?;
		for entry in manager.iter_mut() {
			entry.encryption = Some(EncryptionScheme::generate());
		}
		manager.save()?;
		Ok(())
	}
}
