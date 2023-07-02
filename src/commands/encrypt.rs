use log::*;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Encrypt all maFiles")]
pub struct EncryptCommand;

impl<T> ManifestCommand<T> for EncryptCommand
where
	T: Transport,
{
	fn execute(&self, transport: T, manager: &mut AccountManager) -> anyhow::Result<()> {
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
