use std::sync::{Arc, Mutex};

use log::*;

use crate::{errors::UserError, tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Remove the authenticator from an account.")]
pub struct RemoveCommand;

impl AccountCommand for RemoveCommand {
	fn execute(
		&self,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()> {
		eprintln!(
			"This will remove the mobile authenticator from {} accounts: {}",
			accounts.len(),
			accounts
				.iter()
				.map(|a| a.lock().unwrap().account_name.clone())
				.collect::<Vec<String>>()
				.join(", ")
		);

		match tui::prompt_char("Do you want to continue?", "yN") {
			'y' => {}
			_ => {
				info!("Aborting!");
				return Err(UserError::Aborted.into());
			}
		}

		let mut successful = vec![];
		for a in accounts {
			let mut account = a.lock().unwrap();
			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(&mut account)?;
			}

			match account.remove_authenticator(None) {
				Ok(success) => {
					if success {
						println!("Removed authenticator from {}", account.account_name);
						successful.push(account.account_name.clone());
					} else {
						println!(
							"Failed to remove authenticator from {}",
							account.account_name
						);
						if tui::prompt_char(
							"Would you like to remove it from the manifest anyway?",
							"yN",
						) == 'y'
						{
							successful.push(account.account_name.clone());
						}
					}
				}
				Err(err) => {
					error!(
						"Unexpected error when removing authenticator from {}: {}",
						account.account_name, err
					);
				}
			}
		}

		for account_name in successful {
			manager.remove_account(account_name);
		}

		manager.save()?;
		Ok(())
	}
}
