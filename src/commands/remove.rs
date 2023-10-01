use std::sync::{Arc, Mutex, RwLock};

use log::*;
use steamguard::{steamapi::TwoFactorClient, transport::TransportError, RemoveAuthenticatorError};

use crate::{errors::UserError, tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Remove the authenticator from an account.")]
pub struct RemoveCommand;

impl<T> AccountCommand<T> for RemoveCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<RwLock<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		eprintln!(
			"This will remove the mobile authenticator from {} accounts: {}",
			accounts.len(),
			accounts
				.iter()
				.map(|a| a.read().unwrap().account_name.clone())
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
			let mut account = a.write().unwrap();
			let client = TwoFactorClient::new(transport.clone());

			let mut revocation: Option<String> = None;
			loop {
				match account.remove_authenticator(&client, revocation.as_ref()) {
					Ok(_) => {
						info!("Removed authenticator from {}", account.account_name);
						successful.push(account.account_name.clone());
						break;
					}
					Err(RemoveAuthenticatorError::TransportError(TransportError::Unauthorized)) => {
						error!("Account {} is not logged in", account.account_name);
						crate::do_login(transport.clone(), &mut account, args.password.clone())?;
						continue;
					}
					Err(RemoveAuthenticatorError::IncorrectRevocationCode {
						attempts_remaining,
					}) => {
						error!(
							"Revocation code was incorrect for {} ({} attempts remaining)",
							account.account_name, attempts_remaining
						);
						if attempts_remaining == 0 {
							error!("No attempts remaining, aborting!");
							break;
						}
						eprint!("Enter the revocation code for {}: ", account.account_name);
						let code = tui::prompt();
						revocation = Some(code);
					}
					Err(RemoveAuthenticatorError::MissingRevocationCode) => {
						error!(
							"Account {} does not have a revocation code",
							account.account_name
						);
						eprint!("Enter the revocation code for {}: ", account.account_name);
						let code = tui::prompt();
						revocation = Some(code);
					}
					Err(err) => {
						error!(
							"Unexpected error when removing authenticator from {}: {}",
							account.account_name, err
						);
						break;
					}
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
