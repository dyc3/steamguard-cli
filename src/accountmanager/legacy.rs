use std::{
	fs::File,
	io::{BufReader, Read},
	path::Path,
};

use log::debug;
use serde::Deserialize;
use steamguard::{token::TwoFactorSecret, SecretString, SteamGuardAccount};

use crate::encryption::{EncryptionScheme, EntryEncryptor};

use super::{
	EntryEncryptionParams, EntryLoader, ManifestAccountLoadError, ManifestEntry, ManifestV1,
};

#[derive(Debug, Deserialize)]
pub struct SdaManifest {
	#[serde(default)]
	pub version: u32,
	pub entries: Vec<SdaManifestEntry>,
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
}

impl From<SdaManifest> for ManifestV1 {
	fn from(sda: SdaManifest) -> Self {
		Self {
			version: 1,
			entries: sda.entries.into_iter().map(|e| e.into()).collect(),
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdaManifestEntry {
	pub filename: String,
	#[serde(default, rename = "steamid")]
	pub steam_id: u64,
	#[serde(default, flatten)]
	pub encryption: Option<SdaEntryEncryptionParams>,
}

impl From<SdaManifestEntry> for ManifestEntry {
	fn from(sda: SdaManifestEntry) -> Self {
		Self {
			filename: sda.filename,
			steam_id: sda.steam_id,
			account_name: Default::default(),
			encryption: sda.encryption.map(|e| e.into()),
		}
	}
}

impl EntryLoader<SdaAccount> for SdaManifestEntry {
	fn load(
		&self,
		path: &Path,
		passkey: Option<&String>,
		encryption_params: Option<&EntryEncryptionParams>,
	) -> anyhow::Result<SdaAccount, ManifestAccountLoadError> {
		debug!("loading entry: {:?}", path);
		let file = File::open(path)?;
		let mut reader = BufReader::new(file);
		let account: SdaAccount;
		match (&passkey, encryption_params.as_ref()) {
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
		Ok(account)
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdaEntryEncryptionParams {
	#[serde(rename = "encryption_iv")]
	pub iv: String,
	#[serde(rename = "encryption_salt")]
	pub salt: String,
}

impl From<SdaEntryEncryptionParams> for EntryEncryptionParams {
	fn from(sda: SdaEntryEncryptionParams) -> Self {
		Self {
			iv: sda.iv,
			salt: sda.salt,
			scheme: EncryptionScheme::LegacySdaCompatible,
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdaAccount {
	pub account_name: String,
	pub serial_number: String,
	#[serde(with = "crate::secret_string")]
	pub revocation_code: SecretString,
	pub shared_secret: TwoFactorSecret,
	pub token_gid: String,
	#[serde(with = "crate::secret_string")]
	pub identity_secret: SecretString,
	pub server_time: u64,
	#[serde(with = "crate::secret_string")]
	pub uri: SecretString,
	pub fully_enrolled: bool,
	pub device_id: String,
	#[serde(with = "crate::secret_string")]
	pub secret_1: SecretString,
	#[serde(default, rename = "Session")]
	pub session: Option<secrecy::Secret<steamguard::steamapi::Session>>,
}

impl From<SdaAccount> for SteamGuardAccount {
	fn from(value: SdaAccount) -> Self {
		Self {
			account_name: value.account_name,
			serial_number: value.serial_number,
			revocation_code: value.revocation_code,
			shared_secret: value.shared_secret,
			token_gid: value.token_gid,
			identity_secret: value.identity_secret,
			uri: value.uri,
			device_id: value.device_id,
			secret_1: value.secret_1,
			tokens: None,
			session: value.session,
		}
	}
}
