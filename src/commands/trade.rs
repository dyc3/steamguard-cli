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
	T: Transport,
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
				crate::do_login(&mut account)?;
			}

			info!("{}: Checking for trade confirmations", account.account_name);
			let confirmations: Vec<Confirmation>;
			loop {
				let confirmer = Confirmer::new(&account);

				match confirmer.get_trade_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(ConfirmerError::InvalidTokens) => {
						info!("obtaining new tokens");
						crate::do_login(&mut account)?;
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

			let confirmer = Confirmer::new(&account);
			let mut any_failed = false;
			if self.accept_all {
				info!("accepting all confirmations");
				match confirmer.accept_confirmations(&confirmations) {
					Ok(_) => {}
					Err(err) => {
						warn!("accept confirmation result: {}", err);
						any_failed = true;
						if self.fail_fast {
							return Err(err.into());
						}
					}
				}
			} else if std::io::stdout().is_tty() {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
				match confirmer.accept_confirmations(&accept) {
					Ok(_) => {}
					Err(err) => {
						warn!("accept confirmation result: {}", err);
						any_failed = true;
						if self.fail_fast {
							return Err(err.into());
						}
					}
				}
				match confirmer.deny_confirmations(&deny) {
					Ok(_) => {}
					Err(err) => {
						warn!("deny confirmation result: {}", err);
						any_failed = true;
						if self.fail_fast {
							return Err(err.into());
						}
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
