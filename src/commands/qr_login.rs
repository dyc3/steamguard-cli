use std::sync::{Arc, Mutex};

use log::*;
use qrcode::QrCode;
use secrecy::ExposeSecret;

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Log in to Steam on another device using the QR code that it's displaying.")]
pub struct QrLoginCommand {
	#[clap(
		long,
		help = "The URL that would normally open in the Steam app. This is the URL that the QR code is displaying. It should start with \"https://s.team/...\""
	)]
	pub url: String,
}

impl AccountCommand for QrLoginCommand {
	fn execute(
		&self,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()> {
		ensure!(
			accounts.len() == 1,
			"You can only log in to one account at a time."
		);
	}
}
