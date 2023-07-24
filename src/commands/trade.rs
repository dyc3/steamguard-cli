use std::sync::{Arc, Mutex};

use crossterm::tty::IsTty;
use log::*;
use steamguard::{Confirmation, Confirmer, ConfirmerError};

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Interactive interface for trade confirmations")]
pub struct TradeCommand {
	#[clap(
		short,
		long,
		help = "Accept all open trade confirmations. Does not open interactive interface."
	)]
	pub accept_all: bool,
	#[clap(
		short,
		long,
		help = "If submitting a confirmation response fails, exit immediately."
	)]
	pub fail_fast: bool,
}

impl<T> AccountCommand<T> for TradeCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()> {
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account)?;
			}

			info!("{}: Checking for trade confirmations", account.account_name);
			let confirmations: Vec<Confirmation>;
			loop {
				let confirmer = Confirmer::new(transport.clone(), &account);

				match confirmer.get_trade_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(ConfirmerError::InvalidTokens) => {
						info!("obtaining new tokens");
						crate::do_login(transport.clone(), &mut account)?;
					}
					Err(err) => {
						error!("Failed to get trade confirmations: {}", err);
						return Err(err.into());
					}
				}
			}

			if confirmations.is_empty() {
				info!("{}: No confirmations", account.account_name);
				continue;
			}

			let confirmer = Confirmer::new(transport.clone(), &account);
			let mut any_failed = false;

			fn submit_loop(
				f: impl Fn() -> Result<(), ConfirmerError>,
				fail_fast: bool,
			) -> Result<(), ConfirmerError> {
				let mut attempts = 0;
				loop {
					match f() {
						Ok(_) => break,
						Err(ConfirmerError::InvalidTokens) => {
							error!("Invalid tokens, but they should be valid already. This is weird, stopping.");
							return Err(ConfirmerError::InvalidTokens);
						}
						Err(ConfirmerError::NetworkFailure(err)) => {
							error!("{}", err);
							return Err(ConfirmerError::NetworkFailure(err));
						}
						Err(ConfirmerError::DeserializeError(err)) => {
							error!("Failed to deserialize the response, but the submission may have succeeded: {}", err);
							return Err(ConfirmerError::DeserializeError(err));
						}
						Err(err) => {
							warn!("submit confirmation result: {}", err);
							if fail_fast || attempts >= 3 {
								return Err(err);
							}

							attempts += 1;
							let wait = std::time::Duration::from_secs(3 * attempts);
							info!(
								"retrying in {} seconds (attempt {})",
								wait.as_secs(),
								attempts
							);
							std::thread::sleep(wait);
						}
					}
				}
				Ok(())
			}

			if self.accept_all {
				info!("accepting all confirmations");
				match submit_loop(
					|| confirmer.accept_confirmations(&confirmations),
					self.fail_fast,
				) {
					Ok(_) => {}
					Err(err) => {
						warn!("accept confirmation result: {}", err);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
			} else if std::io::stdout().is_tty() {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
				match submit_loop(|| confirmer.accept_confirmations(&accept), self.fail_fast) {
					Ok(_) => {}
					Err(err) => {
						warn!("accept confirmation result: {}", err);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
				match submit_loop(|| confirmer.deny_confirmations(&deny), self.fail_fast) {
					Ok(_) => {}
					Err(err) => {
						warn!("deny confirmation result: {}", err);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
			} else {
				warn!("not a tty, not showing menu");
				for conf in &confirmations {
					println!("{}", conf.description());
				}
			}

			if any_failed {
				error!("Failed to respond to some confirmations.");
			}
		}

		manager.save()?;
		Ok(())
	}
}
