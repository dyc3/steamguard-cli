use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use steamguard::SteamGuardAccount;

use super::EntryEncryptionParams;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
	pub version: u32,
	pub entries: Vec<ManifestEntry>,

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
	pub steam_id: u64,
	pub account_name: String,
	pub encryption: Option<EntryEncryptionParams>,
}

impl Default for Manifest {
	fn default() -> Self {
		Self {
			version: 1,
			entries: vec![],

			accounts: HashMap::new(),
			folder: "".into(),
			passkey: None,
		}
	}
}
