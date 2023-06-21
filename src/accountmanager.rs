use crate::accountmanager::legacy::SdaManifest;
pub use crate::encryption::EntryEncryptionParams;
use crate::encryption::EntryEncryptor;
use log::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use steamguard::{ExposeSecret, SteamGuardAccount};
use thiserror::Error;

mod legacy;
pub mod manifest;

pub use manifest::*;

#[derive(Debug, Default)]
pub struct AccountManager {
	manifest: Manifest,
	accounts: HashMap<String, Arc<Mutex<SteamGuardAccount>>>,
	folder: String,
	passkey: Option<String>,
}

impl AccountManager {
	/// `path` should be the path to manifest.json
	pub fn new(path: &Path) -> Self {
		Self {
			folder: String::from(path.parent().unwrap().to_str().unwrap()),
			..Default::default()
		}
	}

	pub fn load(path: &Path) -> anyhow::Result<Self, ManifestLoadError> {
		debug!("loading manifest: {:?}", &path);
		let file = File::open(path)?;
		let mut reader = BufReader::new(file);
		let mut buffer = String::new();
		reader.read_to_string(&mut buffer)?;
		let manifest: Manifest = match serde_json::from_str(&buffer) {
			Ok(m) => m,
			Err(orig_err) => match serde_json::from_str::<SdaManifest>(&buffer) {
				Ok(_) => return Err(ManifestLoadError::MigrationNeeded)?,
				Err(_) => return Err(orig_err)?,
			},
		};
		if manifest.version != CURRENT_MANIFEST_VERSION {
			return Err(ManifestLoadError::MigrationNeeded)?;
		}
		let accountmanager = Self {
			manifest,
			folder: String::from(path.parent().unwrap().to_str().unwrap()),
			..Default::default()
		};
		return Ok(accountmanager);
	}

	/// Tells the manager to keep track of the encryption passkey, and use it for encryption when loading or saving accounts.
	pub fn submit_passkey(&mut self, passkey: Option<String>) {
		if let Some(p) = passkey.as_ref() {
			if p.is_empty() {
				panic!("Encryption passkey cannot be empty");
			}
		}
		if passkey.is_some() {
			debug!("passkey was submitted to manifest");
		} else {
			debug!("passkey was revoked from manifest");
		}
		self.passkey = passkey;
	}

	/// Loads all accounts, and registers them.
	pub fn load_accounts(&mut self) -> anyhow::Result<(), ManifestAccountLoadError> {
		let mut accounts = vec![];
		for entry in &self.manifest.entries {
			let account = self.load_account_by_entry(&entry)?;
			accounts.push(account);
		}
		for account in accounts {
			self.register_loaded_account(account);
		}
		Ok(())
	}

	/// Loads an account by account name.
	/// Must call `register_loaded_account` after loading the account.
	fn load_account(
		&self,
		account_name: &String,
	) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>, ManifestAccountLoadError> {
		let entry = self.get_entry(account_name)?;
		self.load_account_by_entry(&entry)
	}

	/// Loads an account from a manifest entry.
	/// Must call `register_loaded_account` after loading the account.
	fn load_account_by_entry(
		&self,
		entry: &ManifestEntry,
	) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>, ManifestAccountLoadError> {
		let path = Path::new(&self.folder).join(&entry.filename);
		debug!("loading account: {:?}", path);
		let file = File::open(path)?;
		let mut reader = BufReader::new(file);
		let account: SteamGuardAccount;
		match (&self.passkey, entry.encryption.as_ref()) {
			(Some(passkey), Some(params)) => {
				let mut ciphertext: Vec<u8> = vec![];
				reader.read_to_end(&mut ciphertext)?;
				let plaintext =
					crate::encryption::LegacySdaCompatible::decrypt(&passkey, params, ciphertext)?;
				if plaintext[0] != '{' as u8 && plaintext[plaintext.len() - 1] != '}' as u8 {
					return Err(ManifestAccountLoadError::IncorrectPasskey);
				}
				let s = std::str::from_utf8(&plaintext).unwrap();
				account = serde_json::from_str(&s)?;
			}
			(None, Some(_)) => {
				return Err(ManifestAccountLoadError::MissingPasskey);
			}
			(_, None) => {
				account = serde_json::from_reader(reader)?;
			}
		};
		let account = Arc::new(Mutex::new(account));
		Ok(account)
	}

	/// Register an account as loaded, so it can be operated on.
	fn register_loaded_account(&mut self, account: Arc<Mutex<SteamGuardAccount>>) {
		let account_name = account.lock().unwrap().account_name.clone();
		self.accounts.insert(account_name, account);
	}

	pub fn account_exists(&self, account_name: &String) -> bool {
		for entry in &self.manifest.entries {
			if &entry.account_name == account_name {
				return true;
			}
		}
		return false;
	}

	pub fn add_account(&mut self, account: SteamGuardAccount) {
		debug!("adding account to manifest: {}", account.account_name);
		let steamid = account
			.session
			.as_ref()
			.map_or(0, |s| s.expose_secret().steam_id);
		self.manifest.entries.push(ManifestEntry {
			filename: format!("{}.maFile", &account.account_name),
			steam_id: steamid,
			account_name: account.account_name.clone(),
			encryption: None,
		});
		self.accounts
			.insert(account.account_name.clone(), Arc::new(Mutex::new(account)));
	}

	pub fn import_account(&mut self, import_path: &String) -> anyhow::Result<()> {
		let path = Path::new(import_path);
		ensure!(path.exists(), "{} does not exist.", import_path);
		ensure!(path.is_file(), "{} is not a file.", import_path);

		let file = File::open(path)?;
		let reader = BufReader::new(file);
		let account: SteamGuardAccount = serde_json::from_reader(reader)?;
		ensure!(
			!self.account_exists(&account.account_name),
			"Account already exists in manifest, please remove it first."
		);
		self.add_account(account);

		return Ok(());
	}

	pub fn remove_account(&mut self, account_name: String) {
		let index = self
			.manifest
			.entries
			.iter()
			.position(|a| a.account_name == account_name)
			.unwrap();
		self.accounts.remove(&account_name);
		self.manifest.entries.remove(index);
	}

	/// Saves the manifest and all loaded accounts.
	pub fn save(&self) -> anyhow::Result<()> {
		info!("Saving manifest and accounts...");
		for account in self
			.accounts
			.values()
			.into_iter()
			.map(|a| a.clone().lock().unwrap().clone())
		{
			let entry = self.get_entry(&account.account_name)?.clone();
			debug!("saving {}", entry.filename);
			let serialized = serde_json::to_vec(&account)?;
			ensure!(
				serialized.len() > 2,
				"Something extra weird happened and the account was serialized into nothing."
			);

			let final_buffer: Vec<u8>;
			match (&self.passkey, entry.encryption.as_ref()) {
				(Some(passkey), Some(params)) => {
					final_buffer = crate::encryption::LegacySdaCompatible::encrypt(
						&passkey, params, serialized,
					)?;
				}
				(None, Some(_)) => {
					bail!("maFiles are encrypted, but no passkey was provided.");
				}
				(_, None) => {
					final_buffer = serialized;
				}
			};

			let path = Path::new(&self.folder).join(&entry.filename);
			let mut file = File::create(path)?;
			file.write_all(final_buffer.as_slice())?;
			file.sync_data()?;
		}
		debug!("saving manifest");
		let manifest_serialized = serde_json::to_string(&self.manifest)?;
		let path = Path::new(&self.folder).join("manifest.json");
		let mut file = File::create(path)?;
		file.write_all(manifest_serialized.as_bytes())?;
		file.sync_data()?;
		Ok(())
	}

	/// Return all loaded accounts. Order is not guarenteed.
	#[allow(dead_code)]
	pub fn get_all_loaded(&self) -> Vec<Arc<Mutex<SteamGuardAccount>>> {
		return self.accounts.values().cloned().into_iter().collect();
	}

	#[allow(dead_code)]
	pub fn get_entry(
		&self,
		account_name: &String,
	) -> anyhow::Result<&ManifestEntry, ManifestAccountLoadError> {
		self.manifest
			.entries
			.iter()
			.find(|e| &e.account_name == account_name)
			.ok_or(ManifestAccountLoadError::MissingManifestEntry)
	}

	#[allow(dead_code)]
	pub fn get_entry_mut(
		&mut self,
		account_name: &String,
	) -> anyhow::Result<&mut ManifestEntry, ManifestAccountLoadError> {
		self.manifest
			.entries
			.iter_mut()
			.find(|e| &e.account_name == account_name)
			.ok_or(ManifestAccountLoadError::MissingManifestEntry)
	}

	pub fn has_passkey(&self) -> bool {
		self.passkey.is_some()
	}

	/// Gets the specified account by name.
	/// Fails if the account does not exist in the manifest entries.
	pub fn get_account(
		&self,
		account_name: &String,
	) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>> {
		let account = self
			.accounts
			.get(account_name)
			.map(|a| a.clone())
			.ok_or(anyhow!("Account not loaded"));
		return account;
	}

	/// Get or load the spcified account.
	pub fn get_or_load_account(
		&mut self,
		account_name: &String,
	) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>, ManifestAccountLoadError> {
		let account = self.get_account(account_name);
		if account.is_ok() {
			return Ok(account.unwrap());
		}
		let account = self.load_account(&account_name)?;
		self.register_loaded_account(account.clone());
		return Ok(account);
	}

	/// Determine if any manifest entries are missing `account_name`.
	fn is_missing_account_name(&self) -> bool {
		self.manifest
			.entries
			.iter()
			.any(|e| e.account_name.is_empty())
	}

	fn has_any_uppercase_in_account_names(&self) -> bool {
		self.manifest
			.entries
			.iter()
			.any(|e| e.account_name != e.account_name.to_lowercase())
	}

	/// Performs auto-upgrades on the manifest. Returns true if any upgrades were performed.
	pub fn auto_upgrade(&mut self) -> anyhow::Result<bool, ManifestAccountLoadError> {
		debug!("Performing auto-upgrade...");
		let mut upgraded = false;
		if self.is_missing_account_name() {
			debug!("Adding missing account names");
			for i in 0..self.manifest.entries.len() {
				let account = self.load_account_by_entry(&self.manifest.entries[i].clone())?;
				self.manifest.entries[i].account_name =
					account.lock().unwrap().account_name.clone();
			}
			upgraded = true;
		}

		if self.has_any_uppercase_in_account_names() {
			debug!("Lowercasing account names");
			for i in 0..self.manifest.entries.len() {
				self.manifest.entries[i].account_name =
					self.manifest.entries[i].account_name.to_lowercase();
			}
			upgraded = true;
		}

		Ok(upgraded)
	}

	pub fn iter(&self) -> impl Iterator<Item = &ManifestEntry> {
		self.manifest.entries.iter()
	}

	pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ManifestEntry> {
		self.manifest.entries.iter_mut()
	}
}

#[derive(Debug, Error)]
pub enum ManifestLoadError {
	#[error("Could not find manifest.json in the specified directory.")]
	Missing(#[from] std::io::Error),
	#[error("Manifest needs to be migrated to the latest format.")]
	MigrationNeeded,
	#[error("Failed to deserialize the manifest.")]
	DeserializationFailed(#[from] serde_json::Error),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum ManifestAccountLoadError {
	#[error("Could not find an entry in the manifest for this account. Check your spelling.")]
	MissingManifestEntry,
	#[error("Manifest accounts are encrypted, but no passkey was provided.")]
	MissingPasskey,
	#[error("Incorrect passkey provided.")]
	IncorrectPasskey,
	#[error("Failed to decrypt account. {self:?}")]
	DecryptionFailed(#[from] crate::encryption::EntryEncryptionError),
	#[error("Failed to deserialize the account.")]
	DeserializationFailed(#[from] serde_json::Error),
	#[error(transparent)]
	Unknown(#[from] anyhow::Error),
}

impl From<block_modes::BlockModeError> for ManifestAccountLoadError {
	fn from(error: block_modes::BlockModeError) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<base64::DecodeError> for ManifestAccountLoadError {
	fn from(error: base64::DecodeError) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<block_modes::InvalidKeyIvLength> for ManifestAccountLoadError {
	fn from(error: block_modes::InvalidKeyIvLength) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}
impl From<std::io::Error> for ManifestAccountLoadError {
	fn from(error: std::io::Error) -> Self {
		return Self::Unknown(anyhow::Error::from(error));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use steamguard::ExposeSecret;
	use tempdir::TempDir;

	#[test]
	fn test_should_save_new_manifest() {
		let tmp_dir = TempDir::new("steamguard-cli-test").unwrap();
		let manifest_path = tmp_dir.path().join("manifest.json");
		let manager = AccountManager::new(manifest_path.as_path());
		assert!(matches!(manager.save(), Ok(_)));
	}

	#[test]
	fn test_should_save_and_load_manifest() -> anyhow::Result<()> {
		let tmp_dir = TempDir::new("steamguard-cli-test")?;
		let manifest_path = tmp_dir.path().join("manifest.json");
		println!("tempdir: {}", manifest_path.display());
		let mut manager = AccountManager::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = String::from("R12345").into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)?;
		manager.add_account(account);
		manager.save()?;

		let mut manager = AccountManager::load(manifest_path.as_path())?;
		assert_eq!(manager.manifest.entries.len(), 1);
		assert_eq!(manager.manifest.entries[0].filename, "asdf1234.maFile");
		manager.load_accounts()?;
		assert_eq!(manager.manifest.entries.len(), manager.accounts.len());
		let account_name = "asdf1234".into();
		assert_eq!(
			manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name,
			"asdf1234"
		);
		assert_eq!(
			manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.revocation_code
				.expose_secret(),
			"R12345"
		);
		assert_eq!(
			manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.shared_secret,
			steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".into()
			)?,
		);
		return Ok(());
	}

	#[test]
	fn test_should_save_and_load_manifest_encrypted() -> anyhow::Result<()> {
		let passkey = Some("password".into());
		let tmp_dir = TempDir::new("steamguard-cli-test")?;
		let manifest_path = tmp_dir.path().join("manifest.json");
		let mut manager = AccountManager::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = String::from("R12345").into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)?;
		manager.add_account(account);
		manager.manifest.entries[0].encryption = Some(EntryEncryptionParams::generate());
		manager.submit_passkey(passkey.clone());
		assert!(matches!(manager.save(), Ok(_)));

		let mut loaded_manager = AccountManager::load(manifest_path.as_path()).unwrap();
		loaded_manager.submit_passkey(passkey);
		assert_eq!(loaded_manager.manifest.entries.len(), 1);
		assert_eq!(
			loaded_manager.manifest.entries[0].filename,
			"asdf1234.maFile"
		);
		let _r = loaded_manager.load_accounts();
		if _r.is_err() {
			eprintln!("{:?}", _r);
		}
		assert!(matches!(_r, Ok(_)));
		assert_eq!(
			loaded_manager.manifest.entries.len(),
			loaded_manager.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.revocation_code
				.expose_secret(),
			"R12345"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.shared_secret,
			steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".into()
			)
			.unwrap(),
		);
		Ok(())
	}

	#[test]
	fn test_should_save_and_load_manifest_encrypted_longer() -> anyhow::Result<()> {
		let passkey = Some("password".into());
		let tmp_dir = TempDir::new("steamguard-cli-test")?;
		let manifest_path = tmp_dir.path().join("manifest.json");
		let mut manager = AccountManager::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = String::from("R12345").into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)
		.unwrap();
		account.uri = String::from("otpauth://;laksdjf;lkasdjf;lkasdj;flkasdjlkf;asjdlkfjslk;adjfl;kasdjf;lksdjflk;asjd;lfajs;ldkfjaslk;djf;lsakdjf;lksdj").into();
		account.token_gid = "asdf1234".into();
		manager.add_account(account);
		manager.submit_passkey(passkey.clone());
		manager.manifest.entries[0].encryption = Some(EntryEncryptionParams::generate());
		manager.save()?;

		let mut loaded_manager = AccountManager::load(manifest_path.as_path())?;
		loaded_manager.submit_passkey(passkey.clone());
		assert_eq!(loaded_manager.manifest.entries.len(), 1);
		assert_eq!(
			loaded_manager.manifest.entries[0].filename,
			"asdf1234.maFile"
		);
		loaded_manager.load_accounts()?;
		assert_eq!(
			loaded_manager.manifest.entries.len(),
			loaded_manager.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.revocation_code
				.expose_secret(),
			"R12345"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.shared_secret,
			steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".into()
			)
			.unwrap(),
		);

		return Ok(());
	}

	#[test]
	fn test_should_import() -> anyhow::Result<()> {
		let tmp_dir = TempDir::new("steamguard-cli-test")?;
		let manifest_path = tmp_dir.path().join("manifest.json");
		let mut manager = AccountManager::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = String::from("R12345").into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)
		.unwrap();
		manager.add_account(account);
		manager.save()?;
		std::fs::remove_file(&manifest_path)?;

		let mut loaded_manager = AccountManager::new(manifest_path.as_path());
		assert!(matches!(
			loaded_manager.import_account(
				&tmp_dir
					.path()
					.join("asdf1234.maFile")
					.into_os_string()
					.into_string()
					.unwrap()
			),
			Ok(_)
		));
		assert_eq!(
			loaded_manager.manifest.entries.len(),
			loaded_manager.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.revocation_code
				.expose_secret(),
			"R12345"
		);
		assert_eq!(
			loaded_manager
				.get_account(&account_name)?
				.lock()
				.unwrap()
				.shared_secret,
			steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".into()
			)
			.unwrap(),
		);

		Ok(())
	}

	// #[test]
	// fn test_sda_compatibility_1() -> anyhow::Result<()> {
	// 	let path = Path::new("src/fixtures/maFiles/compat/1-account/manifest.json");
	// 	assert!(path.is_file());
	// 	let mut manager = AccountManager::load(path)?;
	// 	assert!(matches!(manager.entries.last().unwrap().encryption, None));
	// 	manager.load_accounts()?;
	// 	let account_name = manager.entries.last().unwrap().account_name.clone();
	// 	assert_eq!(
	// 		account_name,
	// 		manager
	// 			.get_account(&account_name)?
	// 			.lock()
	// 			.unwrap()
	// 			.account_name
	// 	);
	// 	Ok(())
	// }

	// #[test]
	// fn test_sda_compatibility_1_encrypted() -> anyhow::Result<()> {
	// 	let path = Path::new("src/fixtures/maFiles/compat/1-account-encrypted/manifest.json");
	// 	assert!(path.is_file());
	// 	let mut manifest = Manifest::load(path)?;
	// 	assert!(matches!(
	// 		manifest.entries.last().unwrap().encryption,
	// 		Some(_)
	// 	));
	// 	manifest.submit_passkey(Some("password".into()));
	// 	manifest.load_accounts()?;
	// 	let account_name = manifest.entries.last().unwrap().account_name.clone();
	// 	assert_eq!(
	// 		account_name,
	// 		manifest
	// 			.get_account(&account_name)?
	// 			.lock()
	// 			.unwrap()
	// 			.account_name
	// 	);
	// 	Ok(())
	// }

	// #[test]
	// fn test_sda_compatibility_no_webcookie() -> anyhow::Result<()> {
	// 	let path = Path::new("src/fixtures/maFiles/compat/no-webcookie/manifest.json");
	// 	assert!(path.is_file());
	// 	let mut manifest = Manifest::load(path)?;
	// 	assert!(matches!(manifest.entries.last().unwrap().encryption, None));
	// 	assert!(matches!(manifest.load_accounts(), Ok(_)));
	// 	let account_name = manifest.entries.last().unwrap().account_name.clone();
	// 	let account = manifest.get_account(&account_name)?;
	// 	assert_eq!(account_name, account.lock().unwrap().account_name);
	// 	assert_eq!(
	// 		account
	// 			.lock()
	// 			.unwrap()
	// 			.session
	// 			.as_ref()
	// 			.unwrap()
	// 			.expose_secret()
	// 			.web_cookie,
	// 		None
	// 	);
	// 	Ok(())
	// }

	// #[test]
	// fn test_sda_compatibility_2() -> anyhow::Result<()> {
	// 	let path = Path::new("src/fixtures/maFiles/compat/2-account/manifest.json");
	// 	assert!(path.is_file());
	// 	let mut manifest = Manifest::load(path)?;
	// 	assert!(matches!(manifest.entries.last().unwrap().encryption, None));
	// 	manifest.load_accounts()?;
	// 	let account_name = manifest.entries[0].account_name.clone();
	// 	let account = manifest.get_account(&account_name)?;
	// 	assert_eq!(account_name, account.lock().unwrap().account_name);
	// 	assert_eq!(
	// 		account.lock().unwrap().revocation_code.expose_secret(),
	// 		"R12345"
	// 	);
	// 	assert_eq!(
	// 		account
	// 			.lock()
	// 			.unwrap()
	// 			.session
	// 			.as_ref()
	// 			.unwrap()
	// 			.expose_secret()
	// 			.steam_id,
	// 		1234
	// 	);

	// 	let account_name = manifest.entries[1].account_name.clone();
	// 	let account = manifest.get_account(&account_name)?;
	// 	assert_eq!(account_name, account.lock().unwrap().account_name);
	// 	assert_eq!(
	// 		account.lock().unwrap().revocation_code.expose_secret(),
	// 		"R56789"
	// 	);
	// 	assert_eq!(
	// 		account
	// 			.lock()
	// 			.unwrap()
	// 			.session
	// 			.as_ref()
	// 			.unwrap()
	// 			.expose_secret()
	// 			.steam_id,
	// 		5678
	// 	);
	// 	Ok(())
	// }

	// #[cfg(test)]
	// mod manifest_upgrades {
	// 	use super::*;

	// 	#[test]
	// 	fn test_missing_account_name() {
	// 		let path = Path::new("src/fixtures/maFiles/compat/missing-account-name/manifest.json");
	// 		assert!(path.is_file());
	// 		let mut manager = AccountManager::load(path).unwrap();
	// 		assert_eq!(manager.entries.len(), 1);
	// 		assert_eq!(manager.entries[0].account_name, "".to_string());
	// 		assert!(manager.is_missing_account_name());

	// 		manager.auto_upgrade().unwrap();
	// 		assert_eq!(manager.entries[0].account_name, "example".to_string());
	// 	}
	// }
}
