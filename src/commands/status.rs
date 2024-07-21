use clap::Parser;
use log::*;
use steamguard::{
	protobufs::service_twofactor::CTwoFactor_Status_Request,
	steamapi::TwoFactorClient,
	transport::{Transport, TransportError},
	SteamGuardAccount,
};

use super::AccountCommand;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Query and print the 2FA status of an account.")]
pub struct StatusCommand;

impl<T> AccountCommand<T> for StatusCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut crate::AccountManager,
		accounts: Vec<std::sync::Arc<std::sync::Mutex<steamguard::SteamGuardAccount>>>,
		args: &super::GlobalArgs,
	) -> anyhow::Result<()> {
		let client = TwoFactorClient::new(transport.clone());

		for account in accounts {
			let mut account = account.lock().unwrap();
			match print_account_status(&mut account, &transport, args, &client) {
				Ok(_) => {}
				Err(e) => {
					error!(
						"Failed to print status for account {}: {}",
						account.account_name, e
					);
				}
			}
		}

		manager.save()?;

		Ok(())
	}
}

fn print_account_status<T>(
	account: &mut SteamGuardAccount,
	transport: &T,
	args: &super::GlobalArgs,
	client: &TwoFactorClient<T>,
) -> anyhow::Result<()>
where
	T: Transport + Clone,
{
	if account.tokens.is_none() {
		crate::do_login(transport.clone(), account, args.password.clone())?;
	}
	let Some(tokens) = account.tokens.as_ref() else {
		bail!(
			"No tokens found for {}. Can't query status if we aren't logged in ourselves.",
			account.account_name
		);
	};
	let mut req = CTwoFactor_Status_Request::new();
	req.set_steamid(account.steam_id);
	let resp = match client.query_status(req.clone(), tokens.access_token()) {
		Ok(resp) => resp,
		Err(TransportError::Unauthorized) => {
			info!("Access token expired, re-logging in...");
			crate::do_login(transport.clone(), account, args.password.clone())?;
			let tokens = account.tokens.as_ref().unwrap();
			client.query_status(req, tokens.access_token())?
		}
		Err(e) => {
			return Err(e.into());
		}
	};
	let data = resp.into_response_data();

	println!("Account: {}", account.account_name);
	println!("Status: {:#?}", data);
	Ok(())
}
