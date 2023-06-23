use std::path::Path;

use log::*;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser, Default)]
#[clap(about = "Import an account with steamguard already set up")]
pub struct ImportCommand {
	#[clap(long, help = "Whether or not the provided maFiles are from SDA.")]
	pub sda: bool,

	#[clap(long, help = "Paths to one or more maFiles, eg. \"./gaben.maFile\"")]
	pub files: Vec<String>,
}

impl ManifestCommand for ImportCommand {
	fn execute(&self, manager: &mut AccountManager) -> anyhow::Result<()> {
		for file_path in self.files.iter() {
			if self.sda {
				let path = Path::new(&file_path);
				let account = crate::accountmanager::migrate::load_and_upgrade_sda_account(path)?;
				manager.add_account(account);
				info!("Imported account: {}", &file_path);
			} else {
				match manager.import_account(file_path) {
					Ok(_) => {
						info!("Imported account: {}", &file_path);
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
