pub use crate::encryption::EntryEncryptionParams;
use crate::encryption::EntryEncryptor;
use log::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use steamguard::SteamGuardAccount;
use thiserror::Error;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
	pub entries: Vec<ManifestEntry>,
	/// Not really used, kept mostly for compatibility with SDA.
	pub encrypted: bool,
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
	accounts: HashMap<String, Arc<Mutex<SteamGuardAccount>>>,
	#[serde(skip)]
	folder: String, // I wanted to use a Path here, but it was too hard to make it work...
	#[serde(skip)]
	passkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
	pub filename: String,
	#[serde(default, rename = "steamid")]
	pub steam_id: u64,
	#[serde(default)]
	pub account_name: String,
	#[serde(default, flatten)]
	pub encryption: Option<EntryEncryptionParams>,
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

			accounts: HashMap::new(),
			folder: "".into(),
			passkey: None,
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

	/// Tells the manifest to keep track of the encryption passkey, and use it for encryption when loading or saving accounts.
	pub fn submit_passkey(&mut self, passkey: Option<String>) {
		if passkey.is_some() {
			debug!("passkey was submitted to manifest");
		}
		else {
			debug!("passkey was revoked from manifest");
		}
		self.passkey = passkey;
	}

	pub fn load_accounts(
		&mut self,
	) -> anyhow::Result<(), ManifestAccountLoadError> {
		let account_names: Vec<String> = self.entries.iter().map(|entry| entry.account_name.clone()).collect();
		for account_name in account_names {
			self.load_account(&account_name)?;
		}
		Ok(())
	}

	fn load_account(
		&mut self,
		account_name: &String
	) -> anyhow::Result<(), ManifestAccountLoadError> {
		let mut entry = self.get_entry_mut(account_name)?.clone();
		let path = Path::new(&self.folder).join(&entry.filename);
		debug!("loading account: {:?}", path);
		let file = File::open(path)?;
		let mut reader = BufReader::new(file);
		let account: SteamGuardAccount;
		match (&self.passkey, entry.encryption.as_ref()) {
			(Some(passkey), Some(params)) => {
				let mut ciphertext: Vec<u8> = vec![];
				reader.read_to_end(&mut ciphertext)?;
				let plaintext = crate::encryption::LegacySdaCompatible::decrypt(
					&passkey, params, ciphertext,
				)?;
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
		entry.account_name = account.account_name.clone();
		self.accounts.insert(entry.account_name.clone(), Arc::new(Mutex::new(account)));
		*self.get_entry_mut(account_name)? = entry;
		Ok(())
	}

	pub fn account_exists(&self, account_name: &String) -> bool {
		for entry in &self.entries {
			if &entry.account_name == account_name {
				return true;
			}
		}
		return false;
	}

	pub fn add_account(&mut self, account: SteamGuardAccount) {
		debug!("adding account to manifest: {}", account.account_name);
		let steamid = account.session.as_ref().map_or(0, |s| s.steam_id);
		self.entries.push(ManifestEntry {
			filename: format!("{}.maFile", &account.account_name),
			steam_id: steamid,
			account_name: account.account_name.clone(),
			encryption: None,
		});
		self.accounts.insert(account.account_name.clone(), Arc::new(Mutex::new(account)));
	}

	pub fn import_account(&mut self, import_path: String) -> anyhow::Result<()> {
		let path = Path::new(&import_path);
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
			.entries
			.iter()
			.position(|a| a.account_name == account_name)
			.unwrap();
		self.accounts.remove(&account_name);
		self.entries.remove(index);
	}

	/// Saves the manifest and all loaded accounts.
	pub fn save(&self) -> anyhow::Result<()> {
		ensure!(
			self.entries.len() == self.accounts.len(),
			"Manifest entries don't match accounts."
		);
		info!("Saving manifest and accounts...");
		for account in self.accounts.values().into_iter().map(|a| a.clone().lock().unwrap().clone()) {
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
		let manifest_serialized = serde_json::to_string(&self)?;
		let path = Path::new(&self.folder).join("manifest.json");
		let mut file = File::create(path)?;
		file.write_all(manifest_serialized.as_bytes())?;
		file.sync_data()?;
		Ok(())
	}

	/// Return all loaded accounts. Order is not guarenteed.
	pub fn get_all_loaded(&self) -> Vec<Arc<Mutex<SteamGuardAccount>>> {
		return self.accounts.values().cloned().into_iter().collect();
	}

	pub fn get_entry(&self, account_name: &String) -> anyhow::Result<&ManifestEntry, ManifestAccountLoadError> {
		self.entries.iter().find(|e| &e.account_name == account_name).ok_or(ManifestAccountLoadError::MissingManifestEntry)
	}

	pub fn get_entry_mut(&mut self, account_name: &String) -> anyhow::Result<&mut ManifestEntry, ManifestAccountLoadError> {
		self.entries.iter_mut().find(|e| &e.account_name == account_name).ok_or(ManifestAccountLoadError::MissingManifestEntry)
	}

	pub fn has_passkey(&self) -> bool {
		self.passkey.is_some()
	}

	/// Gets the specified account by name.
	/// Fails if the account does not exist in the manifest entries.
	pub fn get_account(&self, account_name: &String) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>> {
		let account = self.accounts.get(account_name)
			.map(|a| a.clone()).ok_or(anyhow!("Account not loaded"));
		return account;
	}

	/// Get or load the spcified account.
	pub fn get_or_load_account(&mut self, account_name: &String) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>, ManifestAccountLoadError> {
		let account = self.get_account(account_name);
		if account.is_ok() {
			return Ok(account.unwrap());
		}
		self.load_account(&account_name)?;
		return Ok(self.get_account(account_name)?);
	}
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
	use tempdir::TempDir;

	#[test]
	fn test_should_save_new_manifest() {
		let tmp_dir = TempDir::new("steamguard-cli-test").unwrap();
		let manifest_path = tmp_dir.path().join("manifest.json");
		let manifest = Manifest::new(manifest_path.as_path());
		assert!(matches!(manifest.save(), Ok(_)));
	}

	#[test]
	fn test_should_save_and_load_manifest() -> anyhow::Result<()> {
		let tmp_dir = TempDir::new("steamguard-cli-test")?;
		let manifest_path = tmp_dir.path().join("manifest.json");
		println!("tempdir: {}", manifest_path.display());
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)?;
		manifest.add_account(account);
		manifest.save()?;

		let mut loaded_manifest = Manifest::load(manifest_path.as_path())?;
		assert_eq!(loaded_manifest.entries.len(), 1);
		assert_eq!(loaded_manifest.entries[0].filename, "asdf1234.maFile");
		loaded_manifest.load_accounts()?;
		assert_eq!(
			loaded_manifest.entries.len(),
			loaded_manifest.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().shared_secret,
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
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)?;
		manifest.add_account(account);
		manifest.entries[0].encryption = Some(EntryEncryptionParams::generate());
		manifest.submit_passkey(passkey.clone());
		assert!(matches!(manifest.save(), Ok(_)));

		let mut loaded_manifest = Manifest::load(manifest_path.as_path()).unwrap();
		loaded_manifest.submit_passkey(passkey);
		assert_eq!(loaded_manifest.entries.len(), 1);
		assert_eq!(loaded_manifest.entries[0].filename, "asdf1234.maFile");
		let _r = loaded_manifest.load_accounts();
		if _r.is_err() {
			eprintln!("{:?}", _r);
		}
		assert!(matches!(_r, Ok(_)));
		assert_eq!(
			loaded_manifest.entries.len(),
			loaded_manifest.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().shared_secret,
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
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)
		.unwrap();
		account.uri = "otpauth://;laksdjf;lkasdjf;lkasdj;flkasdjlkf;asjdlkfjslk;adjfl;kasdjf;lksdjflk;asjd;lfajs;ldkfjaslk;djf;lsakdjf;lksdj".into();
		account.token_gid = "asdf1234".into();
		manifest.add_account(account);
		manifest.submit_passkey(passkey.clone());
		manifest.entries[0].encryption = Some(EntryEncryptionParams::generate());
		manifest.save()?;

		let mut loaded_manifest = Manifest::load(manifest_path.as_path())?;
		loaded_manifest.submit_passkey(passkey.clone());
		assert_eq!(loaded_manifest.entries.len(), 1);
		assert_eq!(loaded_manifest.entries[0].filename, "asdf1234.maFile");
		loaded_manifest.load_accounts()?;
		assert_eq!(
			loaded_manifest.entries.len(),
			loaded_manifest.accounts.len()
		);
		let account_name = "asdf1234".into();
		assert_eq!(
		loaded_manifest.get_account(&account_name)?.lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().shared_secret,
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
		let mut manifest = Manifest::new(manifest_path.as_path());
		let mut account = SteamGuardAccount::new();
		account.account_name = "asdf1234".into();
		account.revocation_code = "R12345".into();
		account.shared_secret = steamguard::token::TwoFactorSecret::parse_shared_secret(
			"zvIayp3JPvtvX/QGHqsqKBk/44s=".into(),
		)
		.unwrap();
		manifest.add_account(account);
		manifest.save()?;
		std::fs::remove_file(&manifest_path)?;

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
		let account_name = "asdf1234".into();
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().account_name,
			"asdf1234"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().revocation_code,
			"R12345"
		);
		assert_eq!(
			loaded_manifest.get_account(&account_name)?.lock().unwrap().shared_secret,
			steamguard::token::TwoFactorSecret::parse_shared_secret(
				"zvIayp3JPvtvX/QGHqsqKBk/44s=".into()
			)
			.unwrap(),
		);

		Ok(())
	}

	#[test]
	fn test_sda_compatibility_1() -> anyhow::Result<()> {
		let path = Path::new("src/fixtures/maFiles/compat/1-account/manifest.json");
		assert!(path.is_file());
		let mut manifest = Manifest::load(path)?;
		assert!(matches!(manifest.entries.last().unwrap().encryption, None));
		manifest.load_accounts()?;
		let account_name = manifest.entries.last().unwrap().account_name.clone();
		assert_eq!(
			account_name,
			manifest.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name
		);
		Ok(())
	}

	#[test]
	fn test_sda_compatibility_1_encrypted() -> anyhow::Result<()> {
		let path = Path::new("src/fixtures/maFiles/compat/1-account-encrypted/manifest.json");
		assert!(path.is_file());
		let mut manifest = Manifest::load(path)?;
		assert!(matches!(
			manifest.entries.last().unwrap().encryption,
			Some(_)
		));
		manifest.submit_passkey(Some("password".into()));
		manifest.load_accounts()?;
		let account_name = manifest.entries.last().unwrap().account_name.clone();
		assert_eq!(
			account_name,
			manifest.get_account(&account_name)?
				.lock()
				.unwrap()
				.account_name
		);
		Ok(())
	}

	#[test]
	fn test_sda_compatibility_no_webcookie() -> anyhow::Result<()> {
		let path = Path::new("src/fixtures/maFiles/compat/no-webcookie/manifest.json");
		assert!(path.is_file());
		let mut manifest = Manifest::load(path)?;
		assert!(matches!(manifest.entries.last().unwrap().encryption, None));
		assert!(matches!(manifest.load_accounts(), Ok(_)));
		let account_name = manifest.entries.last().unwrap().account_name.clone();
		let account = manifest.get_account(&account_name)?;
		assert_eq!(
			account_name,
			account
				.lock()
				.unwrap()
				.account_name
		);
		assert_eq!(
			account
				.lock()
				.unwrap()
				.session
				.as_ref()
				.unwrap()
				.web_cookie,
			None
		);
		Ok(())
	}
}
