use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::error::Error;

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

	// #[serde(skip)]
	// pub accounts: Vec<SteamGuardAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
	pub encryption_iv: Option<String>,
	pub encryption_salt: Option<String>,
	pub filename: String,
	#[serde(rename = "steamid")]
	pub steam_id: u64,
}

impl Manifest {
	pub fn load(path: &Path) -> Result<Manifest, Box<dyn Error>> {
		match File::open(path) {
			Ok(file) => {
				let reader = BufReader::new(file);
				match serde_json::from_reader(reader) {
					Ok(manifest) => {
						return Ok(manifest);
					}
					Err(e) => {
						return Err(Box::new(e));
					}
				}
			}
			Err(e) => {
				return Err(Box::new(e));
			}
		}
	}
}
