use log::*;
use phonenumber::PhoneNumber;
use secrecy::ExposeSecret;
use steamguard::{
	accountlinker::{AccountLinkConfirmType, AccountLinkSuccess, RemoveAuthenticatorError},
	phonelinker::PhoneLinker,
	steamapi::PhoneClient,
	token::Tokens,
	AccountLinkError, AccountLinker, FinalizeLinkError,
};

use crate::{tui, AccountManager};

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Set up a new account with steamguard-cli")]
pub struct SetupCommand;

impl<T> ManifestCommand<T> for SetupCommand
where
	T: Transport + Clone,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
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
		let tokens = crate::do_login_raw(transport.clone(), username, args.password.clone())
			.expect("Failed to log in. Account has not been linked.");

		info!("Adding authenticator...");
		let mut linker = AccountLinker::new(transport.clone(), tokens);
		loop {
			match linker.link() {
				Ok(link) => {
					return Self::add_new_account(link, manager, account_name, linker);
				}
				Err(AccountLinkError::MustProvidePhoneNumber) => {
					// As of Dec 12, 2023, Steam no longer appears to require a phone number to add an authenticator. Keeping this code here just in case.
					eprintln!("Looks like you don't have a phone number on this account.");
					do_add_phone_number(transport.clone(), linker.tokens())?;
				}
				Err(AccountLinkError::MustConfirmEmail) => {
					println!("Check your email and click the link.");
					tui::pause();
				}
				Err(AccountLinkError::AuthenticatorPresent) => {
					eprintln!("It looks like there's already an authenticator on this account. If you want to link it to steamguard-cli, you'll need to remove it first. If you remove it using your revocation code (R#####), you'll get a 15 day trade ban.");
					eprintln!("However, you can \"transfer\" the authenticator to steamguard-cli if you have access to the phone number associated with your account. This will cause you to get only a 2 day trade ban.");
					eprintln!("If you were using SDA or WinAuth, you can import it into steamguard-cli with the `import` command, and have no trade ban.");
					eprintln!("You can't have the same authenticator on steamguard-cli and the steam mobile app at the same time.");

					eprintln!("\nHere are your options:");
					eprintln!("[T] Transfer authenticator to steamguard-cli (2 day trade ban)");
					eprintln!("[R] Revoke authenticator with revocation code (15 day trade ban)");
					eprintln!("[A] Abort setup");
					let answer = tui::prompt_char("What would you like to do?", "Tra");
					match answer {
						't' => return Self::transfer_new_account(linker, manager),
						'r' => {
							loop {
								let revocation_code =
									tui::prompt_non_empty("Enter your revocation code (R#####): ");
								match linker.remove_authenticator(Some(&revocation_code)) {
									Ok(_) => break,
									Err(RemoveAuthenticatorError::IncorrectRevocationCode {
										attempts_remaining,
									}) => {
										error!(
											"Revocation code was incorrect ({} attempts remaining)",
											attempts_remaining
										);
										if attempts_remaining == 0 {
											error!("No attempts remaining, aborting!");
											bail!("Failed to remove authenticator: no attempts remaining")
										}
									}
									Err(err) => {
										error!("Failed to remove authenticator: {}", err);
									}
								}
							}
						}
						_ => {
							info!("Aborting account linking.");
							return Err(AccountLinkError::AuthenticatorPresent.into());
						}
					}
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
	}
}

impl SetupCommand {
	/// Add a new account to the manifest after linking has started.
	fn add_new_account<T>(
		link: AccountLinkSuccess,
		manager: &mut AccountManager,
		account_name: String,
		mut linker: AccountLinker<T>,
	) -> Result<(), anyhow::Error>
	where
		T: Transport + Clone,
	{
		let mut server_time = link.server_time();
		let phone_number_hint = link.phone_number_hint().to_owned();
		let confirm_type = link.confirm_type();
		manager.add_account(link.into_account());
		match manager.save() {
			Ok(_) => {}
			Err(err) => {
				error!("Aborting the account linking process because we failed to save the manifest. This is really bad. Here is the error: {}", err);
				eprintln!(
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
		eprintln!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code.expose_secret());
		tui::pause();
		debug!("attempting link finalization");
		let confirm_code = match confirm_type {
			AccountLinkConfirmType::Email => {
				eprintln!(
					"A code has been sent to the email address associated with this account."
				);
				tui::prompt_non_empty("Enter email code: ")
			}
			AccountLinkConfirmType::SMS => {
				eprintln!(
					"A code has been sent to your phone number ending in {}.",
					phone_number_hint
				);
				tui::prompt_non_empty("Enter SMS code: ")
			}
			AccountLinkConfirmType::Unknown(t) => {
				error!("Unknown link confirm type: {}", t);
				bail!("Unknown link confirm type: {}", t);
			}
		};
		let mut tries = 0;
		loop {
			match linker.finalize(server_time, &mut account, confirm_code.clone()) {
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
		drop(account);
		info!("Verifying authenticator status...");
		let status =
			linker.query_status(&manager.get_account(&account_name).unwrap().lock().unwrap())?;
		if status.state() == 0 {
			debug!(
				"authenticator state: {} -- did not actually finalize",
				status.state()
			);
			manager.remove_account(&account_name);
			manager.save()?;
			bail!("Authenticator finalization was unsuccessful. You may have entered the wrong confirm code in the previous step. Try again.");
		}
		info!("Authenticator finalized.");
		match manager.save() {
			Ok(_) => {}
			Err(err) => {
				error!(
					"Failed to save manifest, but we were able to save it before. {}",
					err
				);
				return Err(err);
			}
		}
		eprintln!(
			"Authenticator has been finalized. Please actually write down your revocation code: {}",
			revocation_code.expose_secret()
		);
		Ok(())
	}

	/// Transfer an existing authenticator to steamguard-cli.
	fn transfer_new_account<T>(
		mut linker: AccountLinker<T>,
		manager: &mut AccountManager,
	) -> anyhow::Result<()>
	where
		T: Transport + Clone,
	{
		info!("Transferring authenticator to steamguard-cli");
		linker.transfer_start()?;

		let account: SteamGuardAccount;
		loop {
			let sms_code = tui::prompt_non_empty("Enter SMS code: ");
			match linker.transfer_finish(sms_code) {
				Ok(acc) => {
					account = acc;
					break;
				}
				Err(err) => {
					error!("Failed to transfer authenticator: {}", err);
				}
			}
		}
		info!("Transfer successful, adding account to manifest");
		let revocation_code = account.revocation_code.clone();
		eprintln!(
			"Take a moment to write down your revocation code: {}",
			revocation_code.expose_secret()
		);

		manager.add_account(account);

		manager.save()?;

		eprintln!(
			"Make sure you have your revocation code written down: {}",
			revocation_code.expose_secret()
		);
		Ok(())
	}
}

pub fn do_add_phone_number<T: Transport>(transport: T, tokens: &Tokens) -> anyhow::Result<()> {
	let client = PhoneClient::new(transport);

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
