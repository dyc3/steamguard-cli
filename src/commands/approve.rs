use crate::commands::AccountCommand;
use crate::{commands::GlobalArgs, AccountManager};
use clap::Parser;
use crossterm::tty::IsTty;
use log::*;
use std::sync::{Arc, Mutex};
use steamguard::approver::Challenge;
use steamguard::protobufs::enums::ESessionPersistence;
use steamguard::protobufs::steammessages_auth_steamclient::EAuthTokenPlatformType;
use steamguard::transport::Transport;
use steamguard::{LoginApprover, SteamGuardAccount};

#[derive(Debug, Clone, Parser)]
#[clap(about = "Approve or deny pending login sessions")]
pub struct ApproveCommand {
	#[clap(
		short,
		long,
		help = "Blindly approve all pending login sessions without prompting."
	)]
	pub approve_all: bool,
}

impl<T> AccountCommand<T> for ApproveCommand
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
		for a in accounts {
			let mut account = a.lock().unwrap();

			if !account.is_logged_in() {
				info!("Account does not have tokens, logging in");
				crate::do_login(transport.clone(), &mut account, args.password.clone())?;
			}

			let Some(tokens) = account.tokens.as_ref() else {
				error!(
					"No tokens found for {}. Can't approve login if we aren't logged in ourselves.",
					account.account_name
				);
				return Err(anyhow!("No tokens found for {}", account.account_name));
			};

			let mut approver = LoginApprover::new(transport.clone(), tokens);

			let sessions = approver.list_auth_sessions()?;
			if sessions.is_empty() {
				info!("No pending sessions to approve");
				return Ok(());
			}

			info!("Found {} pending sessions", sessions.len());

			if self.approve_all {
				info!("Approving all pending sessions");
				for client_id in sessions {
					let challenge = Challenge::new(1, client_id);
					approver.approve(
						&account,
						challenge,
						ESessionPersistence::k_ESessionPersistence_Persistent,
					)?;
				}
			} else if std::io::stdout().is_tty() {
				let total = sessions.len();
				for (session_idx, client_id) in sessions.iter().enumerate() {
					let session = approver.get_auth_session_info(*client_id)?;

					let platform_str = match session.platform_type() {
						EAuthTokenPlatformType::k_EAuthTokenPlatformType_Unknown => "Unknown",
						EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient => {
							"Steam Client"
						}
						EAuthTokenPlatformType::k_EAuthTokenPlatformType_WebBrowser => {
							"Web Browser"
						}
						EAuthTokenPlatformType::k_EAuthTokenPlatformType_MobileApp => "Mobile App",
					};
					eprintln!(
						"[{session_idx}/{total}] Do you recognize this login attempt?

	Account: {}
	IP: {}
	Geolocation: {}
	City: {}, {}, {}
	Platform: {}
	Device Friendly Name: {}\n",
						account.account_name,
						session.ip(),
						session.geoloc(),
						session.city(),
						session.state(),
						session.country(),
						platform_str,
						session.device_friendly_name(),
					);

					let decision = crate::tui::prompt_char(
						"What do you want to do? [A]pprove, [t]emporarily approve, [d]eny, [s]kip?",
						"Atds",
					);

					let challenge = Challenge::new(1, *client_id);
					match decision {
						'a' => {
							info!("Approving persistent session {}", client_id);
							approver.approve(
								&account,
								challenge,
								ESessionPersistence::k_ESessionPersistence_Persistent,
							)?;
						}
						't' => {
							info!("Approving ephemeral session {}", client_id);
							approver.approve(
								&account,
								challenge,
								ESessionPersistence::k_ESessionPersistence_Persistent,
							)?;
						}
						'd' => {
							info!("Denying session {}", client_id);
							approver.deny(&account, challenge)?;
						}
						's' => {
							info!("Skipping session {}", client_id);
						}
						_ => {
							error!("Invalid choice");
						}
					}
				}
			} else {
				info!("Non-interactive mode, skipping all sessions");
			}
		}
		manager.save()?;
		Ok(())
	}
}
