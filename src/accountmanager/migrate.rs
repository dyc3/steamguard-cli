// notes for migration:
// account names must be made lowercase

use std::{fs::File, io::Read, path::Path};

use steamguard::SteamGuardAccount;

use super::{
	legacy::{SdaAccount, SdaManifest},
	manifest::ManifestV1,
	Manifest,
};

pub fn load_and_migrate(manifest_path: &Path) -> anyhow::Result<Manifest> {
	backup_file(manifest_path)?;

	let mut file = File::open(manifest_path)?;
	let mut buffer = String::new();
	file.read_to_string(&mut buffer)?;
	let mut manifest: MigratingManifest = deserialize_manifest(buffer)?;

	let folder = manifest_path.parent().unwrap();
	let mut accounts = manifest.load_all_accounts(folder)?;

	while !manifest.is_latest() {
		manifest = manifest.upgrade();

		for account in accounts.iter_mut() {
			*account = account.clone().upgrade();
		}
	}

	Ok(manifest.into())
}

fn backup_file(path: &Path) -> anyhow::Result<()> {
	let backup_path = path.with_extension("bak");
	std::fs::copy(path, backup_path)?;
	Ok(())
}

#[derive(Debug)]
enum MigratingManifest {
	SDA(SdaManifest),
	ManifestV1(ManifestV1),
}

impl MigratingManifest {
	pub fn upgrade(self) -> Self {
		match self {
			Self::SDA(sda) => Self::ManifestV1(sda.into()),
			Self::ManifestV1(_) => self,
		}
	}

	pub fn is_latest(&self) -> bool {
		match self {
			Self::ManifestV1(_) => true,
			_ => false,
		}
	}

	pub fn version(&self) -> u32 {
		match self {
			Self::SDA(_) => 0,
			Self::ManifestV1(_) => 1,
		}
	}

	pub fn load_all_accounts(&self, folder: &Path) -> anyhow::Result<Vec<MigratingAccount>> {
		let files: Vec<String> = match self {
			Self::SDA(sda) => sda.entries.iter().map(|e| e.filename.clone()).collect(),
			Self::ManifestV1(manifest) => manifest
				.entries
				.iter()
				.map(|e| e.filename.clone())
				.collect(),
		};

		let mut accounts = vec![];
		for file in files {
			let file = Path::join(folder, file);
			let text = std::fs::read_to_string(&file)?;
			let account = deserialize_account(text, self.version())?;
			accounts.push(account);
		}

		Ok(accounts)
	}
}

impl From<MigratingManifest> for Manifest {
	fn from(migrating: MigratingManifest) -> Self {
		match migrating {
			MigratingManifest::ManifestV1(manifest) => manifest.into(),
			_ => panic!("Manifest is not at the latest version!"),
		}
	}
}

fn deserialize_manifest(text: String) -> anyhow::Result<MigratingManifest> {
	let json: serde_json::Value = serde_json::from_str(&text)?;
	if json["version"] == 1 {
		let manifest: ManifestV1 = serde_json::from_str(&text)?;
		Ok(MigratingManifest::ManifestV1(manifest))
	} else {
		let manifest: SdaManifest = serde_json::from_str(&text)?;
		Ok(MigratingManifest::SDA(manifest))
	}
}

#[derive(Debug, Clone)]
enum MigratingAccount {
	SDA(SdaAccount),
	ManifestV1(SteamGuardAccount), // TODO: get a new type for this
}

impl MigratingAccount {
	pub fn upgrade(self) -> Self {
		match self {
			Self::SDA(sda) => Self::ManifestV1(sda.into()),
			Self::ManifestV1(_) => self,
		}
	}
}

fn deserialize_account(text: String, version: u32) -> anyhow::Result<MigratingAccount> {
	match version {
		0 => Ok(MigratingAccount::SDA(serde_json::from_str(&text)?)),
		1 => Ok(MigratingAccount::ManifestV1(serde_json::from_str(&text)?)),
		_ => panic!("Unknown manifest version: {}", version),
	}
}
