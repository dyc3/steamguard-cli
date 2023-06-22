use std::sync::{Arc, Mutex};

use log::info;

use steamguard::SteamGuardAccount;

use crate::do_login;

pub fn do_subcmd_test_login(
	selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> anyhow::Result<()> {
	for account in selected_accounts {
		let mut account = account.lock().unwrap();
		do_login(&mut account)?;
		info!("Logged in successfully!");
	}
	Ok(())
}
