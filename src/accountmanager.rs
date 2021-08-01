use log::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use steamguard::SteamGuardAccount;

#[derive(Debug, Serialize, Deserialize)]
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
    pub accounts: Vec<SteamGuardAccount>,
    #[serde(skip)]
    folder: String, // I wanted to use a Path here, but it was too hard to make it work...
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
    pub fn load(path: &Path) -> anyhow::Result<Manifest> {
        debug!("loading manifest: {:?}", &path);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut manifest: Manifest = serde_json::from_reader(reader)?;
        manifest.folder = String::from(path.parent().unwrap().to_str().unwrap());
        return Ok(manifest);
    }

    pub fn load_accounts(&mut self) -> anyhow::Result<()> {
        for entry in &self.entries {
            let path = Path::new(&self.folder).join(&entry.filename);
            debug!("loading account: {:?}", path);
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let account: SteamGuardAccount = serde_json::from_reader(reader)?;
            self.accounts.push(account);
        }
        Ok(())
    }

    pub fn add_account(&mut self, account: &SteamGuardAccount) {
        debug!("adding account to manifest: {}", account.account_name);
        let steamid = account.session.clone().unwrap().steam_id;
        self.accounts.push(account.clone());
        self.entries.push(ManifestEntry {
            filename: format!("{}.maFile", account.account_name),
            steam_id: steamid,
            encryption_iv: None,
            encryption_salt: None,
        });
    }

    pub fn save(&self) -> anyhow::Result<()> {
        ensure!(
            self.entries.len() == self.accounts.len(),
            "Manifest entries don't match accounts."
        );
        for (entry, account) in self.entries.iter().zip(&self.accounts) {
            debug!("saving {}", entry.filename);
            let serialized = serde_json::to_string(&account)?;
            ensure!(
                serialized.len() > 2,
                "Something extra weird happened and the account was serialized into nothing."
            );
            let path = Path::new(&self.folder).join(&entry.filename);
            let mut file = File::create(path)?;
            file.write_all(serialized.as_bytes())?;
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
}
