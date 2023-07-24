use log::*;

use crate::{AccountManager, ManifestAccountLoadError};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Decrypt all maFiles")]
pub struct DecryptCommand;

impl<T> ManifestCommand<T> for DecryptCommand
where
	T: Transport,
{
	fn execute(&self, _transport: T, manager: &mut AccountManager) -> anyhow::Result<()> {
		load_accounts_with_prompts(manager)?;

		#[cfg(feature = "keyring")]
		if let Some(keyring_id) = manager.keyring_id() {
			match crate::encryption::clear_passkey(keyring_id.clone()) {
				Ok(_) => {
					info!("Cleared passkey from keyring");
					manager.clear_keyring_id();
				}
				Err(e) => warn!("Failed to clear passkey from keyring: {}", e),
			}
		}
		for entry in manager.iter_mut() {
			entry.encryption = None;
		}
		manager.submit_passkey(None);
		manager.save()?;
		Ok(())
	}
}

fn load_accounts_with_prompts(manager: &mut AccountManager) -> anyhow::Result<()> {
	loop {
		match manager.load_accounts() {
			Ok(_) => return Ok(()),
			Err(
				ManifestAccountLoadError::MissingPasskey
				| ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manager.has_passkey() {
					error!("Incorrect passkey");
				}
				let passkey = Some(crate::tui::prompt_passkey()?);
				manager.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}
}
