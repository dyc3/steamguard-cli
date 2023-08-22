use std::path::Path;

use log::*;

use crate::{accountmanager::ManifestAccountImportError, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser, Default)]
#[clap(
	about = "Import an account with steamguard already set up. It must not be encrypted. If you haven't used steamguard-cli before, you probably don't need to use this command."
)]
pub struct ImportCommand {
	#[clap(long, help = "Whether or not the provided maFiles are from SDA.")]
	pub sda: bool,

	#[clap(long, help = "Paths to one or more maFiles, eg. \"./gaben.maFile\"")]
	pub files: Vec<String>,
}

impl<T> ManifestCommand<T> for ImportCommand
where
	T: Transport,
{
	fn execute(&self, _transport: T, manager: &mut AccountManager) -> anyhow::Result<()> {
		for file_path in self.files.iter() {
			debug!("loading entry: {:?}", file_path);
			if self.sda {
				let path = Path::new(&file_path);
				let account =
					crate::accountmanager::migrate::load_and_upgrade_external_account(path)?;
				manager.add_account(account);
				info!("Imported account: {}", &file_path);
			} else {
				match manager.import_account(file_path) {
					Ok(_) => {
						info!("Imported account: {}", &file_path);
					}
					Err(ManifestAccountImportError::AlreadyExists { .. }) => {
						warn!("Account already exists: {} -- Ignoring", &file_path);
					}
					Err(ManifestAccountImportError::DeserializationFailed(err)) => {
						warn!("Failed to import account: {} {}", &file_path, err);
						warn!("If this file came from SDA, try using --sda");
					}
					Err(err) => {
						bail!("Failed to import account: {} {}", &file_path, err);
					}
				}
			}
		}

		manager.save()?;
		Ok(())
	}
}
