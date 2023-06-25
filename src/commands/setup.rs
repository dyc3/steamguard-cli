use log::*;
use phonenumber::PhoneNumber;
use secrecy::ExposeSecret;
use steamguard::{
	accountlinker::AccountLinkSuccess, phonelinker::PhoneLinker, steamapi::PhoneClient,
	token::Tokens, transport::WebApiTransport, AccountLinkError, AccountLinker, FinalizeLinkError,
};

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Set up a new account with steamguard-cli")]
pub struct SetupCommand;

impl ManifestCommand for SetupCommand {
	fn execute(&self, manager: &mut AccountManager) -> anyhow::Result<()> {
		eprintln!("Log in to the account that you want to link to steamguard-cli");
		eprint!("Username: ");
		let username = tui::prompt().to_lowercase();
		let account_name = username.clone();
		if manager.account_exists(&username) {
			bail!(
				"Account {} already exists in manifest, remove it first",
				username
			);
		}
		info!("Logging in to {}", username);
		let tokens =
			crate::do_login_raw(username).expect("Failed to log in. Account has not been linked.");

		info!("Adding authenticator...");
		let mut linker = AccountLinker::new(tokens);
		let link: AccountLinkSuccess;
		loop {
			match linker.link() {
				Ok(a) => {
					link = a;
					break;
				}
				Err(AccountLinkError::MustProvidePhoneNumber) => {
					eprintln!("Looks like you don't have a phone number on this account.");
					do_add_phone_number(linker.tokens())?;
				}
				Err(AccountLinkError::AuthenticatorPresent) => {
					println!("An authenticator is already present on this account.");
					bail!("An authenticator is already present on this account.");
				}
				Err(AccountLinkError::MustConfirmEmail) => {
					println!("Check your email and click the link.");
					tui::pause();
				}
				Err(err) => {
					error!(
						"Failed to link authenticator. Account has not been linked. {}",
						err
					);
					return Err(err.into());
				}
			}
		}
		let mut server_time = link.server_time();
		let phone_number_hint = link.phone_number_hint().to_owned();
		manager.add_account(link.into_account());
		match manager.save() {
			Ok(_) => {}
			Err(err) => {
				error!("Aborting the account linking process because we failed to save the manifest. This is really bad. Here is the error: {}", err);
				println!(
				"Just in case, here is the account info. Save it somewhere just in case!\n{:#?}",
				manager.get_account(&account_name).unwrap().lock().unwrap()
			);
				return Err(err);
			}
		}

		let account_arc = manager
			.get_account(&account_name)
			.expect("account was not present in manifest");
		let mut account = account_arc.lock().unwrap();

		println!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code.expose_secret());
		tui::pause();

		debug!("attempting link finalization");
		println!(
			"A code has been sent to your phone number ending in {}.",
			phone_number_hint
		);
		print!("Enter SMS code: ");
		let sms_code = tui::prompt();
		let mut tries = 0;
		loop {
			match linker.finalize(server_time, &mut account, sms_code.clone()) {
				Ok(_) => break,
				Err(FinalizeLinkError::WantMore { server_time: s }) => {
					server_time = s;
					debug!("steam wants more 2fa codes (tries: {})", tries);
					tries += 1;
					if tries >= 30 {
						error!("Failed to finalize: unable to generate valid 2fa codes");
						bail!("Failed to finalize: unable to generate valid 2fa codes");
					}
				}
				Err(err) => {
					error!("Failed to finalize: {}", err);
					return Err(err.into());
				}
			}
		}
		let revocation_code = account.revocation_code.clone();
		drop(account); // explicitly drop the lock so we don't hang on the mutex

		println!("Authenticator finalized.");
		match manager.save() {
			Ok(_) => {}
			Err(err) => {
				println!(
					"Failed to save manifest, but we were able to save it before. {}",
					err
				);
				return Err(err);
			}
		}

		println!(
			"Authenticator has been finalized. Please actually write down your revocation code: {}",
			revocation_code.expose_secret()
		);

		Ok(())
	}
}

pub fn do_add_phone_number(tokens: &Tokens) -> anyhow::Result<()> {
	let client = PhoneClient::new(WebApiTransport::new());

	let linker = PhoneLinker::new(client, tokens.clone());

	let phone_number: PhoneNumber;
	loop {
		eprintln!("Enter your phone number, including country code, in this format: +1 1234567890");
		eprint!("Phone number: ");
		let number = tui::prompt();
		match phonenumber::parse(None, &number) {
			Ok(p) => {
				phone_number = p;
				break;
			}
			Err(err) => {
				error!("Failed to parse phone number: {}", err);
			}
		}
	}

	let resp = linker.set_account_phone_number(phone_number)?;

	eprintln!(
		"Please click the link in the email sent to {}",
		resp.confirmation_email_address()
	);
	tui::pause();

	debug!("sending phone verification code");
	linker.send_phone_verification_code(0)?;

	loop {
		eprint!("Enter the code sent to your phone: ");
		let code = tui::prompt();

		match linker.verify_account_phone_with_code(code) {
			Ok(_) => break,
			Err(err) => {
				error!("Failed to verify phone number: {}", err);
			}
		}
	}

	info!("Successfully added phone number to account");

	Ok(())
}
