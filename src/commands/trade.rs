use std::sync::{Arc, Mutex};

use crossterm::tty::IsTty;
use log::*;
use steamguard::Confirmation;

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

impl AccountCommand for TradeCommand {
	fn execute(
		&self,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	) -> anyhow::Result<()> {
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(&mut account)?;
			}

			info!("Checking for trade confirmations");
			let confirmations: Vec<Confirmation>;
			loop {
				match account.get_trade_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(err) => {
						error!("Failed to get trade confirmations: {:#?}", err);
						info!("failed to get trade confirmations, asking user to log in");
						crate::do_login(&mut account)?;
					}
				}
			}

			let mut any_failed = false;
			if self.accept_all {
				info!("accepting all confirmations");
				for conf in &confirmations {
					let result = account.accept_confirmation(conf);
					if result.is_err() {
						warn!("accept confirmation result: {:?}", result);
						any_failed = true;
						if self.fail_fast {
							return result;
						}
					} else {
						debug!("accept confirmation result: {:?}", result);
					}
				}
			} else if std::io::stdout().is_tty() {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
				for conf in &accept {
					let result = account.accept_confirmation(conf);
					if result.is_err() {
						warn!("accept confirmation result: {:?}", result);
						any_failed = true;
						if self.fail_fast {
							return result;
						}
					} else {
						debug!("accept confirmation result: {:?}", result);
					}
				}
				for conf in &deny {
					let result = account.deny_confirmation(conf);
					debug!("deny confirmation result: {:?}", result);
					if result.is_err() {
						warn!("deny confirmation result: {:?}", result);
						any_failed = true;
						if self.fail_fast {
							return result;
						}
					} else {
						debug!("deny confirmation result: {:?}", result);
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
