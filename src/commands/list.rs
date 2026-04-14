use clap::Parser;
use steamguard::transport::Transport;

use crate::{accountmanager::ManifestEntry, AccountManager};

use super::{GlobalArgs, ManifestCommand};

#[derive(Debug, Clone, Parser)]
#[clap(about = "List all accounts from the manifest.")]
pub struct ListCommand;

impl<T> ManifestCommand<T> for ListCommand
where
	T: Transport,
{
	fn execute(
		&self,
		_transport: T,
		manager: &mut AccountManager,
		_args: &GlobalArgs,
	) -> anyhow::Result<()> {
		let account_names = account_names(manager.iter());
		if account_names.is_empty() {
			println!("No accounts found in manifest.");
			return Ok(());
		}

		for account_name in account_names {
			println!("{}", account_name);
		}

		Ok(())
	}
}

fn account_names<'a>(entries: impl Iterator<Item = &'a ManifestEntry>) -> Vec<&'a str> {
	entries.map(|entry| entry.account_name.as_str()).collect()
}

#[cfg(test)]
mod tests {
	use crate::accountmanager::{manifest::Manifest, ManifestEntry};

	use super::account_names;

	#[test]
	fn account_names_preserves_manifest_order() {
		let entries = vec![
			ManifestEntry {
				filename: String::from("beta.maFile"),
				steam_id: 2,
				account_name: String::from("beta"),
				encryption: None,
			},
			ManifestEntry {
				filename: String::from("alpha.maFile"),
				steam_id: 1,
				account_name: String::from("alpha"),
				encryption: None,
			},
		];

		let names = account_names(entries.iter());

		assert_eq!(names, vec!["beta", "alpha"]);
	}

	#[test]
	fn account_names_empty_manifest() {
		let manifest = Manifest::default();
		let names = account_names(manifest.entries.iter());

		assert!(names.is_empty());
	}
}
