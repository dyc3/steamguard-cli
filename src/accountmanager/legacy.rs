use serde::{Deserialize, Serialize};

#[deprecated]
#[derive(Debug, Serialize, Deserialize)]
pub struct SdaManifest {
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

#[deprecated]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdaManifestEntry {
	pub filename: String,
	#[serde(default, rename = "steamid")]
	pub steam_id: u64,
	#[serde(default)]
	pub account_name: String,
	#[serde(default, flatten)]
	pub encryption: Option<SdaEntryEncryptionParams>,
}

#[deprecated]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdaEntryEncryptionParams {
	#[serde(rename = "encryption_iv")]
	pub iv: String,
	#[serde(rename = "encryption_salt")]
	pub salt: String,
}
