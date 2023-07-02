use std::sync::{Arc, Mutex};

use log::*;
use steamguard::{
	transport::{self, WebApiTransport},
	QrApprover, QrApproverError,
};

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

impl<T> AccountCommand<T> for QrLoginCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		_manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()> {
		ensure!(
			accounts.len() == 1,
			"You can only log in to one account at a time."
		);

		let mut account = accounts[0].lock().unwrap();

		info!("Approving login to {}", account.account_name);

		if account.tokens.is_none() {
			crate::do_login(transport, &mut account)?;
		}

		loop {
			let Some(tokens) = account.tokens.as_ref() else {
				error!("No tokens found for {}. Can't approve login if we aren't logged in ourselves.", account.account_name);
				return Err(anyhow!("No tokens found for {}", account.account_name));
			};

			let mut approver = QrApprover::new(transport, tokens);
			match approver.approve(&account, &self.url) {
				Ok(_) => {
					info!("Login approved.");
					break;
				}
				Err(QrApproverError::Unauthorized) => {
					warn!("tokens are invalid. Attempting to log in again.");
					crate::do_login(transport, &mut account)?;
				}
				Err(e) => {
					error!("Failed to approve login: {}", e);
					break;
				}
			}
		}

		Ok(())
	}
}
