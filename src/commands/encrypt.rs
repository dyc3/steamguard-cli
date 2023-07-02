use log::*;

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Encrypt all maFiles")]
pub struct EncryptCommand;

impl<T> ManifestCommand<T> for EncryptCommand
where
	T: Transport,
{
	fn execute(&self, _transport: T, manager: &mut AccountManager) -> anyhow::Result<()> {
		if !manager.has_passkey() {
			let mut passkey;
			loop {
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				if let Some(p) = passkey.as_ref() {
					if p.is_empty() {
						error!("Passkey cannot be empty, try again.");
						continue;
					}
				}
				let passkey_confirm =
					rpassword::prompt_password_stdout("Confirm encryption passkey: ").ok();
				if passkey == passkey_confirm {
					break;
				}
				error!("Passkeys do not match, try again.");
			}
			let passkey = passkey.map(SecretString::new);

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
			entry.encryption = Some(crate::accountmanager::EntryEncryptionParams::generate());
		}
		manager.save()?;
		Ok(())
	}
}
