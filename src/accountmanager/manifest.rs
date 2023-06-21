use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use steamguard::SteamGuardAccount;

use super::EntryEncryptionParams;

pub const CURRENT_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
	pub version: u32,
	pub entries: Vec<ManifestEntry>,
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
			version: CURRENT_MANIFEST_VERSION,
			entries: vec![],
		}
	}
}
