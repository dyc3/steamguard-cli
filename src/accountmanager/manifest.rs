use serde::{Deserialize, Serialize};

use super::EntryEncryptionParams;

pub const CURRENT_MANIFEST_VERSION: u32 = 1;
pub type Manifest = ManifestV1;
pub type ManifestEntry = ManifestEntryV1;

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestV1 {
	pub version: u32,
	pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntryV1 {
	pub filename: String,
	pub steam_id: u64,
	pub account_name: String,
	pub encryption: Option<EntryEncryptionParams>,
}

impl Default for ManifestV1 {
	fn default() -> Self {
		Self {
			version: 1,
			entries: vec![],
		}
	}
}
