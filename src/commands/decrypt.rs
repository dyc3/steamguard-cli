use log::*;

use crate::{AccountManager, ManifestAccountLoadError};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Decrypt all maFiles")]
pub struct DecryptCommand;

impl ManifestCommand for DecryptCommand {
	fn execute(&self, manager: &mut AccountManager) -> anyhow::Result<()> {
		load_accounts_with_prompts(manager)?;
		for mut entry in manager.iter_mut() {
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
				let passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manager.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}
}
