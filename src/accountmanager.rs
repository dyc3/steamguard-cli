use log::*;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{cell::Cell, fs::File};
use steamguard::SteamGuardAccount;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
	pub encrypted: bool,
	pub entries: Vec<ManifestEntry>,
	/// Not implemented, kept for compatibility with SDA.
	pub first_run: bool,
	/// Not implemented, kept for compatibility with SDA.
	pub periodic_checking: bool,
	/// Not implemented, kept for compatibility with SDA.
	pub periodic_checking_interval: i32,
	/// Not implemented, kept for compatibility with SDA.
	pub periodic_checking_checkall: bool,
	/// Not implemented, kept for compatibility with SDA.
	pub auto_confirm_market_transactions: bool,
	/// Not implemented, kept for compatibility with SDA.
	pub auto_confirm_trades: bool,

	#[serde(skip)]
	pub accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	#[serde(skip)]
	folder: String, // I wanted to use a Path here, but it was too hard to make it work...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
	pub encryption_iv: Option<String>,
	pub encryption_salt: Option<String>,
	pub filename: String,
	#[serde(rename = "steamid")]
	pub steam_id: u64,
	pub account_name: String,
}

impl Default for Manifest {
	fn default() -> Self {
		Manifest {
			encrypted: false,
			entries: vec![],
			first_run: false,
			periodic_checking: false,
			periodic_checking_interval: 0,
			periodic_checking_checkall: false,
			auto_confirm_market_transactions: false,
			auto_confirm_trades: false,

			accounts: vec![],
			folder: "".into(),
		}
	}
}

impl Manifest {
	/// `path` should be the path to manifest.json
	pub fn new(path: &Path) -> Self {
		Manifest {
			folder: String::from(path.parent().unwrap().to_str().unwrap()),
			..Default::default()
		}
	}

	pub fn load(path: &Path) -> anyhow::Result<Self> {
		debug!("loading manifest: {:?}", &path);
		let file = File::open(path)?;
		let reader = BufReader::new(file);
		let mut manifest: Manifest = serde_json::from_reader(reader)?;
		manifest.folder = String::from(path.parent().unwrap().to_str().unwrap());
		return Ok(manifest);
	}

	pub fn load_accounts(&mut self) -> anyhow::Result<()> {
		for entry in &self.entries {
			let path = Path::new(&self.folder).join(&entry.filename);
			debug!("loading account: {:?}", path);
			let file = File::open(path)?;
			let reader = BufReader::new(file);
			let account: SteamGuardAccount = serde_json::from_reader(reader)?;
			ensure!(
				account.account_name == entry.account_name,
				"Account name in file does not match manifest entry."
			);
			self.accounts.push(Arc::new(Mutex::new(account)));
		}
		Ok(())
	}

	pub fn add_account(&mut self, account: SteamGuardAccount) {
		debug!("adding account to manifest: {}", account.account_name);
		let steamid = account.session.as_ref().map_or(0, |s| s.steam_id);
		self.entries.push(ManifestEntry {
			filename: format!("{}.maFile", &account.account_name),
			steam_id: steamid,
			account_name: account.account_name.clone(),
			encryption_iv: None,
			encryption_salt: None,
		});
		self.accounts.push(Arc::new(Mutex::new(account)));
	}

	pub fn import_account(&mut self, import_path: String) -> anyhow::Result<()> {
		let path = Path::new(&import_path);
		ensure!(path.exists(), "{} does not exist.", import_path);
		ensure!(path.is_file(), "{} is not a file.", import_path);

		let file = File::open(path)?;
		let reader = BufReader::new(file);
		let account: SteamGuardAccount = serde_json::from_reader(reader)?;
		self.add_account(account);

		return Ok(());
	}

	pub fn remove_account(&mut self, account_name: String) {
		let index = self
			.accounts
			.iter()
			.position(|a| a.lock().unwrap().account_name == account_name)
			.unwrap();
		self.accounts.remove(index);
		self.entries.remove(index);
	}

	pub fn save(&self) -> anyhow::Result<()> {
		ensure!(
			self.entries.len() == self.accounts.len(),
			"Manifest entries don't match accounts."
		);
		for (entry, account) in self.entries.iter().zip(&self.accounts) {
			debug!("saving {}", entry.filename);
			let serialized = serde_json::to_string(account.as_ref())?;
			ensure!(
				serialized.len() > 2,
				"Something extra weird happened and the account was serialized into nothing."
			);
			let path = Path::new(&self.folder).join(&entry.filename);
			let mut file = File::create(path)?;
			file.write_all(serialized.as_bytes())?;
			file.sync_data()?;
		}
		debug!("saving manifest");
		let manifest_serialized = serde_json::to_string(&self)?;
		let path = Path::new(&self.folder).join("manifest.json");
		let mut file = File::create(path)?;
		file.write_all(manifest_serialized.as_bytes())?;
		file.sync_data()?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempdir::TempDir;

	#[test]
	fn test_should_save_new_manifest() {
		let tmp_dir = TempDir::new("steamguard-cli-test").unwrap();
		let manifest_path = tmp_dir.path().join("manifest.json");
		let manifest = Manifest::new(manifest_path.as_path());
		assert!(matches!(manifest.save(), Ok(_)));
	}

	#[test]
	fn test_should_save_and_load_manifest() {
		let tmp_dir = TempDir::new("steamguard-cli-test").unwrap();
		let manifest_path = tmp_dir.path().join("manifest.json");
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = "secret".into();
		manifest.add_account(account);
		assert!(matches!(manifest.save(), Ok(_)));

		let mut loaded_manifest = Manifest::load(manifest_path.as_path()).unwrap();
		assert_eq!(loaded_manifest.entries.len(), 1);
		assert_eq!(loaded_manifest.entries[0].filename, "asdf1234.maFile");
		assert!(matches!(loaded_manifest.load_accounts(), Ok(_)));
		assert_eq!(
			loaded_manifest.entries.len(),
			loaded_manifest.accounts.len()
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().shared_secret,
			"secret"
		);
	}

	#[test]
	fn test_should_import() {
		let tmp_dir = TempDir::new("steamguard-cli-test").unwrap();
		let manifest_path = tmp_dir.path().join("manifest.json");
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = "secret".into();
		manifest.add_account(account);
		assert!(matches!(manifest.save(), Ok(_)));
		std::fs::remove_file(&manifest_path).unwrap();

		let mut loaded_manifest = Manifest::new(manifest_path.as_path());
		assert!(matches!(
			loaded_manifest.import_account(
				tmp_dir
					.path()
					.join("asdf1234.maFile")
					.into_os_string()
					.into_string()
					.unwrap()
			),
			Ok(_)
		));
		assert_eq!(
			loaded_manifest.entries.len(),
			loaded_manifest.accounts.len()
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.accounts[0].lock().unwrap().shared_secret,
			"secret"
		);
	}
}
