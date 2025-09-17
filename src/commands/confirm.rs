use std::sync::{Arc, Mutex};

use crossterm::tty::IsTty;
use log::*;
use steamguard::{Confirmation, Confirmer, ConfirmerError};

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Interactive interface for steam mobile confirmations")]
pub struct ConfirmCommand {
	#[clap(
		short,
		long,
		help = "Accept all open mobile confirmations. Does not open interactive interface."
	)]
	pub accept_all: bool,
	#[clap(
		short,
		long,
		help = "If submitting a confirmation response fails, exit immediately."
	)]
	pub fail_fast: bool,
	#[clap(
		long,
		help = "Accept only the latest/most recent confirmation"
	)]
	pub latest: bool,
	#[clap(
		long,
		help = "Accept confirmation with specific trade offer ID"
	)]
	pub trade_offer_id: Option<String>,
}

#[derive(Debug, Clone, Parser)]
#[clap(about = "Decline steam mobile confirmations")]
pub struct DeclineCommand {
	#[clap(
		short,
		long,
		help = "Decline all open mobile confirmations. Does not open interactive interface."
	)]
	pub decline_all: bool,
	#[clap(
		short,
		long,
		help = "If submitting a confirmation response fails, exit immediately."
	)]
	pub fail_fast: bool,
	#[clap(
		long,
		help = "Decline only the latest/most recent confirmation"
	)]
	pub latest: bool,
	#[clap(
		long,
		help = "Decline confirmation with specific trade offer ID"
	)]
	pub trade_offer_id: Option<String>,
}

impl ConfirmCommand {
	fn validate_options(&self) -> anyhow::Result<()> {
		let option_count = [
			self.accept_all,
			self.latest,
			self.trade_offer_id.is_some(),
		].iter().filter(|&&x| x).count();
		
		if option_count > 1 {
			return Err(anyhow::anyhow!(
				"Only one of --accept-all, --latest, or --trade-offer-id can be specified"
			));
		}
		
		Ok(())
	}
}

impl DeclineCommand {
	fn validate_options(&self) -> anyhow::Result<()> {
		let option_count = [
			self.decline_all,
			self.latest,
			self.trade_offer_id.is_some(),
		].iter().filter(|&&x| x).count();
		
		if option_count > 1 {
			return Err(anyhow::anyhow!(
				"Only one of --decline-all, --latest, or --trade-offer-id can be specified"
			));
		}
		
		Ok(())
	}
}

impl<T> AccountCommand<T> for ConfirmCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		self.validate_options()?;
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account, args.password.clone())?;
			}

			info!("{}: Checking for confirmations", account.account_name);
			let confirmations: Vec<Confirmation>;
			loop {
				let confirmer = Confirmer::new(transport.clone(), &account);

				match confirmer.get_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(ConfirmerError::InvalidTokens) => {
						info!("obtaining new tokens");
						crate::do_login(transport.clone(), &mut account, args.password.clone())?;
					}
					Err(err) => {
						error!("Failed to get confirmations: {}", err);
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
				submit: impl Fn() -> Result<(), ConfirmerError>,
				fail_fast: bool,
			) -> Result<(), ConfirmerError> {
				let mut attempts = 0;
				loop {
					match submit() {
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
					|| confirmer.accept_confirmations_bulk(&confirmations),
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
			} else if self.latest {
				info!("accepting latest confirmation");
				if let Some(latest_conf) = confirmations.first() {
					match submit_loop(
						|| confirmer.accept_confirmations_bulk(&vec![latest_conf.clone()]),
						self.fail_fast,
					) {
						Ok(_) => {
							info!("Successfully accepted latest confirmation: {}", latest_conf.description());
						}
						Err(err) => {
							warn!("accept confirmation result: {}", err);
							if self.fail_fast {
								return Err(err.into());
							}
							any_failed = true;
						}
					}
				} else {
					info!("No confirmations to accept");
				}
			} else if let Some(ref trade_id) = self.trade_offer_id {
				info!("looking for confirmation with trade offer ID: {}", trade_id);
				let matching_conf = confirmations.iter().find(|conf| {
					// Match against creator_id which contains the trade offer ID
					conf.creator_id == *trade_id
				});
				
				if let Some(conf) = matching_conf {
					info!("found matching confirmation: {}", conf.description());
					match submit_loop(
						|| confirmer.accept_confirmations_bulk(&vec![conf.clone()]),
						self.fail_fast,
					) {
						Ok(_) => {
							info!("Successfully accepted confirmation for trade offer ID: {}", trade_id);
						}
						Err(err) => {
							warn!("accept confirmation result: {}", err);
							if self.fail_fast {
								return Err(err.into());
							}
							any_failed = true;
						}
					}
				} else {
					warn!("No confirmation found for trade offer ID: {}", trade_id);
					// List available confirmations for debugging
					for conf in &confirmations {
						info!("Available confirmation - ID: {}, Creator ID: {}, Description: {}", 
							conf.id, conf.creator_id, conf.description());
					}
				}
			} else if std::io::stdout().is_tty() {
				let (accept, deny) = tui::prompt_confirmation_menu(confirmations)?;
				match submit_loop(
					|| confirmer.accept_confirmations_bulk(&accept),
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
				match submit_loop(|| confirmer.deny_confirmations_bulk(&deny), self.fail_fast) {
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

impl<T> AccountCommand<T> for DeclineCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		self.validate_options()?;
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account, args.password.clone())?;
			}

			info!("{}: Checking for confirmations", account.account_name);
			let confirmations: Vec<Confirmation>;
			loop {
				let confirmer = Confirmer::new(transport.clone(), &account);

				match confirmer.get_confirmations() {
					Ok(confs) => {
						confirmations = confs;
						break;
					}
					Err(ConfirmerError::InvalidTokens) => {
						info!("obtaining new tokens");
						crate::do_login(transport.clone(), &mut account, args.password.clone())?;
					}
					Err(err) => {
						error!("Failed to get confirmations: {}", err);
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
				submit: impl Fn() -> Result<(), ConfirmerError>,
				fail_fast: bool,
			) -> Result<(), ConfirmerError> {
				let mut attempts = 0;
				loop {
					match submit() {
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
							warn!("submit decline result: {}", err);
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

			if self.decline_all {
				info!("declining all confirmations");
				match submit_loop(
					|| confirmer.deny_confirmations_bulk(&confirmations),
					self.fail_fast,
				) {
					Ok(_) => {}
					Err(err) => {
						warn!("decline confirmation result: {}", err);
						if self.fail_fast {
							return Err(err.into());
						}
						any_failed = true;
					}
				}
			} else if self.latest {
				info!("declining latest confirmation");
				if let Some(latest_conf) = confirmations.first() {
					match submit_loop(
						|| confirmer.deny_confirmations_bulk(&vec![latest_conf.clone()]),
						self.fail_fast,
					) {
						Ok(_) => {
							info!("Successfully declined latest confirmation: {}", latest_conf.description());
						}
						Err(err) => {
							warn!("decline confirmation result: {}", err);
							if self.fail_fast {
								return Err(err.into());
							}
							any_failed = true;
						}
					}
				} else {
					info!("No confirmations to decline");
				}
			} else if let Some(ref trade_id) = self.trade_offer_id {
				info!("looking for confirmation with trade offer ID: {}", trade_id);
				let matching_conf = confirmations.iter().find(|conf| {
					// Match against creator_id which contains the trade offer ID
					conf.creator_id == *trade_id
				});
				
				if let Some(conf) = matching_conf {
					info!("found matching confirmation: {}", conf.description());
					match submit_loop(
						|| confirmer.deny_confirmations_bulk(&vec![conf.clone()]),
						self.fail_fast,
					) {
						Ok(_) => {
							info!("Successfully declined confirmation for trade offer ID: {}", trade_id);
						}
						Err(err) => {
							warn!("decline confirmation result: {}", err);
							if self.fail_fast {
								return Err(err.into());
							}
							any_failed = true;
						}
					}
				} else {
					warn!("No confirmation found for trade offer ID: {}", trade_id);
					// List available confirmations for debugging
					for conf in &confirmations {
						info!("Available confirmation - ID: {}, Creator ID: {}, Description: {}", 
							conf.id, conf.creator_id, conf.description());
					}
				}
			} else if std::io::stdout().is_tty() {
				warn!("Interactive mode not supported for decline command. Use --decline-all, --latest, or --trade-offer-id");
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
