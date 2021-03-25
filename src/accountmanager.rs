use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
	pub encrypted: bool,
	pub entries: Vec<ManifestEntry>,
	pub first_run: bool,
	pub periodic_checking: bool,
	pub periodic_checking_interval: i32,
	pub periodic_checking_checkall: bool,
	pub auto_confirm_market_transactions: bool,
	pub auto_confirm_trades: bool,

	#[serde(skip)]
	pub accounts: Vec<SteamGuardAccount>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
	pub encryption_iv: String,
	pub encryption_salt: String,
	pub filename: String,
	pub steam_id: u64,
}


