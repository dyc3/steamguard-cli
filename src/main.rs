extern crate rpassword;
use clap::{crate_version, App, Arg, ArgMatches, Parser, Subcommand};
use log::*;
use std::{
	io::{stdout, Write},
	path::Path,
	sync::{Arc, Mutex},
};
use steamguard::{
	steamapi, AccountLinkError, AccountLinker, Confirmation, FinalizeLinkError, LoginError,
	SteamGuardAccount, UserLogin,
};

use crate::{accountmanager::ManifestAccountLoadError, cli::Subcommands};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate base64;
extern crate dirs;
#[cfg(test)]
extern crate proptest;
extern crate ring;
mod accountmanager;
mod cli;
mod demos;
mod encryption;
mod errors;
mod tui;

fn cli() -> App<'static> {
	App::new("steamguard-cli")
		.version(crate_version!())
		.bin_name("steamguard")
		.author("dyc3 (Carson McManus)")
		.about("Generate Steam 2FA codes and confirm Steam trades from the command line.")
		.arg(
			Arg::with_name("username")
				.long("username")
				.short('u')
				.takes_value(true)
				.help("Select the account you want by steam username. Case-sensitive. By default, the first account in the manifest is selected.")
				.conflicts_with("all")
		)
		.arg(
			Arg::with_name("all")
				.long("all")
				.short('a')
				.takes_value(false)
				.help("Select all accounts in the manifest.")
				.conflicts_with("username")
		)
		.arg(
			Arg::with_name("mafiles-path")
				.long("mafiles-path")
				.short('m')
				.default_value("~/maFiles")
				.help("Specify which folder your maFiles are in. This should be a path to a folder that contains manifest.json.")
		)
		.arg(
			Arg::with_name("passkey")
				.long("passkey")
				.short('p')
				.help("Specify your encryption passkey.")
				.takes_value(true)
		)
		// .subcommand(
		// 	App::new("completion")
		// 		.about("Generate shell completions")
		// 		.arg(
		// 			Arg::with_name("shell")
		// 				.long("shell")
		// 				.takes_value(true)
		// 				.possible_values(&Shell::variants())
		// 		)
		// )
		.subcommand(
			App::new("trade")
				.about("Interactive interface for trade confirmations")
				.arg(
					Arg::with_name("accept-all")
						.short('a')
						.long("accept-all")
						.takes_value(false)
						.help("Accept all open trade confirmations. Does not open interactive interface.")
				)
				.arg(
					Arg::with_name("fail-fast")
						.takes_value(false)
						.help("If submitting a confirmation response fails, exit immediately.")
				)
		)
		.subcommand(
			App::new("setup")
			.about("Set up a new account with steamguard-cli")
		)
		.subcommand(
			App::new("import")
				.about("Import an account with steamguard already set up")
				.arg(
					Arg::with_name("files")
						.required(true)
						.multiple(true)
				)
		)
		.subcommand(
			App::new("remove")
			.about("Remove the authenticator from an account.")
		)
		.subcommand(
			App::new("encrypt")
				.about("Encrypt maFiles.")
		)
		.subcommand(
			App::new("decrypt")
				.about("Decrypt maFiles.")
		)
		.subcommand(
			App::new("debug")
			.arg(
				Arg::with_name("demo-conf-menu")
				.help("Show an example confirmation menu using dummy data.")
				.takes_value(false)
			)
		)
}

fn main() {
	std::process::exit(match run() {
		Ok(_) => 0,
		Err(e) => {
			error!("{:?}", e);
			255
		}
	});
}

fn run() -> anyhow::Result<()> {
	let new_args = cli::Args::parse();
	println!("{:?}", new_args);

	let matches = cli().get_matches();

	stderrlog::new()
		.verbosity(new_args.verbosity as usize)
		.module(module_path!())
		.module("steamguard")
		.init()
		.unwrap();

	match new_args.sub {
		Some(cli::Subcommands::Debug(args)) => {
			if args.demo_conf_menu {
				demos::demo_confirmation_menu();
			}
			return Ok(());
		},
		// Subcommand::Completions{shell} => {
		// 	// cli().gen_completions_to(
		// 	// 	"steamguard",
		// 	// 	Shell::from_str(completion_matches.value_of("shell").unwrap()).unwrap(),
		// 	// 	&mut std::io::stdout(),
		// 	// );
		// 	return Ok(());
		// },
		_ => {},
	};

	let mafiles_dir = if let Some(mafiles_path) = new_args.mafiles_path {
		mafiles_path
	} else {
		get_mafiles_dir()
	};
	info!("reading manifest from {}", mafiles_dir);
	let path = Path::new(&mafiles_dir).join("manifest.json");
	let mut manifest: accountmanager::Manifest;
	if !path.exists() {
		error!("Did not find manifest in {}", mafiles_dir);
		match tui::prompt_char(
			format!("Would you like to create a manifest in {} ?", mafiles_dir).as_str(),
			"Yn",
		) {
			'n' => {
				info!("Aborting!");
				return Err(errors::UserError::Aborted.into());
			}
			_ => {}
		}
		std::fs::create_dir_all(mafiles_dir)?;

		manifest = accountmanager::Manifest::new(path.as_path());
		manifest.save()?;
	} else {
		manifest = accountmanager::Manifest::load(path.as_path())?;
	}

	let mut passkey: Option<String> = new_args.passkey;
	manifest.submit_passkey(passkey);

	loop {
		match manifest.auto_upgrade() {
			Ok(upgraded) => {
				if upgraded {
					info!("Manifest auto-upgraded");
					manifest.save()?;
				} else {
					debug!("Manifest is up to date");
				}
				break;
			}
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manifest.has_passkey() {
					error!("Incorrect passkey");
				}
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manifest.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}

	match new_args.sub {
		Some(cli::Subcommands::Setup(args)) => {
			return do_subcmd_setup(args, &mut manifest);
		},
		Some(cli::Subcommands::Import(args)) => {todo!()},
		Some(cli::Subcommands::Encrypt(args)) => {todo!()},
		Some(cli::Subcommands::Decrypt(args)) => {todo!()},
		_ => {},
	}

	if matches.is_present("setup") {

	} else if let Some(import_matches) = matches.subcommand_matches("import") {
		for file_path in import_matches.values_of("files").unwrap() {
			match manifest.import_account(file_path.into()) {
				Ok(_) => {
					info!("Imported account: {}", file_path);
				}
				Err(err) => {
					bail!("Failed to import account: {} {}", file_path, err);
				}
			}
		}

		manifest.save()?;
		return Ok(());
	} else if matches.is_present("encrypt") {
		if !manifest.has_passkey() {
			loop {
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				let passkey_confirm =
					rpassword::prompt_password_stdout("Confirm encryption passkey: ").ok();
				if passkey == passkey_confirm {
					break;
				}
				error!("Passkeys do not match, try again.");
			}
			manifest.submit_passkey(passkey);
		}
		manifest.load_accounts()?;
		for entry in &mut manifest.entries {
			entry.encryption = Some(accountmanager::EntryEncryptionParams::generate());
		}
		manifest.save()?;
		return Ok(());
	} else if matches.is_present("decrypt") {
		manifest.load_accounts()?;
		for entry in &mut manifest.entries {
			entry.encryption = None;
		}
		manifest.submit_passkey(None);
		manifest.save()?;
		return Ok(());
	}

	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>>;
	loop {
		match get_selected_accounts(&matches, &mut manifest) {
			Ok(accounts) => {
				selected_accounts = accounts;
				break;
			}
			Err(
				accountmanager::ManifestAccountLoadError::MissingPasskey
				| accountmanager::ManifestAccountLoadError::IncorrectPasskey,
			) => {
				if manifest.has_passkey() {
					error!("Incorrect passkey");
				}
				passkey = rpassword::prompt_password_stdout("Enter encryption passkey: ").ok();
				manifest.submit_passkey(passkey);
			}
			Err(e) => {
				error!("Could not load accounts: {}", e);
				return Err(e.into());
			}
		}
	}

	debug!(
		"selected accounts: {:?}",
		selected_accounts
			.iter()
			.map(|a| a.lock().unwrap().account_name.clone())
			.collect::<Vec<String>>()
	);

	match new_args.sub.as_ref() {
		Some(cli::Subcommands::Trade(args)) => {
			for a in selected_accounts.iter_mut() {
				let mut account = a.lock().unwrap();

				info!("Checking for trade confirmations");
				let confirmations: Vec<Confirmation>;
				loop {
					match account.get_trade_confirmations() {
						Ok(confs) => {
							confirmations = confs;
							break;
						}
						Err(_) => {
							info!("failed to get trade confirmations, asking user to log in");
							do_login(&mut account)?;
						}
					}
				}

				let mut any_failed = false;
				if args.accept_all {
					info!("accepting all confirmations");
					for conf in &confirmations {
						let result = account.accept_confirmation(conf);
						if result.is_err() {
							warn!("accept confirmation result: {:?}", result);
							any_failed = true;
							if args.fail_fast {
								return result;
							}
						} else {
							debug!("accept confirmation result: {:?}", result);
						}
					}
				} else {
					if termion::is_tty(&stdout()) {
						let (accept, deny) = tui::prompt_confirmation_menu(confirmations);
						for conf in &accept {
							let result = account.accept_confirmation(conf);
							if result.is_err() {
								warn!("accept confirmation result: {:?}", result);
								any_failed = true;
								if args.fail_fast {
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
								if args.fail_fast {
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
				}

				if any_failed {
					error!("Failed to respond to some confirmations.");
				}
			}

			manifest.save()?;
		},
		Some(cli::Subcommands::Remove(args)) => {
			println!(
				"This will remove the mobile authenticator from {} accounts: {}",
				selected_accounts.len(),
				selected_accounts
					.iter()
					.map(|a| a.lock().unwrap().account_name.clone())
					.collect::<Vec<String>>()
					.join(", ")
			);

			match tui::prompt_char("Do you want to continue?", "yN") {
				'y' => {}
				_ => {
					info!("Aborting!");
					return Err(errors::UserError::Aborted.into());
				}
			}

			let mut successful = vec![];
			for a in selected_accounts {
				let account = a.lock().unwrap();
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
							match tui::prompt_char(
								"Would you like to remove it from the manifest anyway?",
								"yN",
							) {
								'y' => {
									successful.push(account.account_name.clone());
								}
								_ => {}
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
				manifest.remove_account(account_name);
			}

			manifest.save()?;
		},
		Some(s) => {
			error!("Unknown subcommand: {:?}", s);
		},
		_ => {
			debug!("No subcommand given, assuming user wants a 2fa code");

			let server_time = steamapi::get_server_time();
			debug!("Time used to generate codes: {}", server_time);
			for account in selected_accounts {
				info!(
					"Generating code for {}",
					account.lock().unwrap().account_name
				);
				trace!("{:?}", account);
				let code = account.lock().unwrap().generate_code(server_time);
				println!("{}", code);
			}
		}
	}

	Ok(())
}

fn get_selected_accounts(
	matches: &ArgMatches,
	manifest: &mut accountmanager::Manifest,
) -> anyhow::Result<Vec<Arc<Mutex<SteamGuardAccount>>>, ManifestAccountLoadError> {
	let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];

	if matches.is_present("all") {
		manifest.load_accounts()?;
		for entry in &manifest.entries {
			selected_accounts.push(manifest.get_account(&entry.account_name).unwrap().clone());
		}
	} else {
		let entry = if matches.is_present("username") {
			manifest.get_entry(&matches.value_of("username").unwrap().into())
		} else {
			manifest
				.entries
				.first()
				.ok_or(ManifestAccountLoadError::MissingManifestEntry)
		}?;

		let account_name = entry.account_name.clone();
		let account = manifest.get_or_load_account(&account_name)?;
		selected_accounts.push(account);
	}
	return Ok(selected_accounts);
}

fn do_login(account: &mut SteamGuardAccount) -> anyhow::Result<()> {
	if account.account_name.len() > 0 {
		println!("Username: {}", account.account_name);
	} else {
		print!("Username: ");
		account.account_name = tui::prompt();
	}
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	account.session = Some(do_login_impl(
		account.account_name.clone(),
		password,
		Some(account),
	)?);
	return Ok(());
}

fn do_login_raw(username: String) -> anyhow::Result<steamapi::Session> {
	let _ = std::io::stdout().flush();
	let password = rpassword::prompt_password_stdout("Password: ").unwrap();
	if password.len() > 0 {
		debug!("password is present");
	} else {
		debug!("password is empty");
	}
	return do_login_impl(username, password, None);
}

fn do_login_impl(
	username: String,
	password: String,
	account: Option<&SteamGuardAccount>,
) -> anyhow::Result<steamapi::Session> {
	// TODO: reprompt if password is empty
	let mut login = UserLogin::new(username, password);
	let mut loops = 0;
	loop {
		match login.login() {
			Ok(s) => {
				return Ok(s);
			}
			Err(LoginError::Need2FA) => match account {
				Some(a) => {
					let server_time = steamapi::get_server_time();
					login.twofactor_code = a.generate_code(server_time);
				}
				None => {
					print!("Enter 2fa code: ");
					login.twofactor_code = tui::prompt();
				}
			},
			Err(LoginError::NeedCaptcha { captcha_gid }) => {
				debug!("need captcha to log in");
				login.captcha_text = tui::prompt_captcha_text(&captcha_gid);
			}
			Err(LoginError::NeedEmail) => {
				println!("You should have received an email with a code.");
				print!("Enter code: ");
				login.email_code = tui::prompt();
			}
			Err(r) => {
				error!("Fatal login result: {:?}", r);
				bail!(r);
			}
		}
		loops += 1;
		if loops > 2 {
			error!("Too many loops. Aborting login process, to avoid getting rate limited.");
			bail!("Too many loops. Login process aborted to avoid getting rate limited.");
		}
	}
}

fn get_mafiles_dir() -> String {
	let paths = vec![
		Path::new(&dirs::config_dir().unwrap()).join("steamguard-cli/maFiles"),
		Path::new(&dirs::home_dir().unwrap()).join("maFiles"),
	];

	for path in &paths {
		if path.join("manifest.json").is_file() {
			return path.to_str().unwrap().into();
		}
	}

	return paths[0].to_str().unwrap().into();
}

fn do_subcmd_setup(args: cli::ArgsSetup, manifest: &mut accountmanager::Manifest) -> anyhow::Result<()> {
	println!("Log in to the account that you want to link to steamguard-cli");
	print!("Username: ");
	let username = if args.username.is_some() {
		let u = args.username.unwrap();
		println!("{}", u);
		u
	} else {
		tui::prompt()
	};
	let account_name = username.clone();
	if manifest.account_exists(&username) {
		bail!(
			"Account {} already exists in manifest, remove it first",
			username
		);
	}
	let session =
		do_login_raw(username).expect("Failed to log in. Account has not been linked.");

	let mut linker = AccountLinker::new(session);
	let account: SteamGuardAccount;
	loop {
		match linker.link() {
			Ok(a) => {
				account = a;
				break;
			}
			Err(AccountLinkError::MustRemovePhoneNumber) => {
				println!("There is already a phone number on this account, please remove it and try again.");
				bail!("There is already a phone number on this account, please remove it and try again.");
			}
			Err(AccountLinkError::MustProvidePhoneNumber) => {
				println!("Enter your phone number in the following format: +1 123-456-7890");
				print!("Phone number: ");
				linker.phone_number = tui::prompt().replace(&['(', ')', '-'][..], "");
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
	manifest.add_account(account);
	match manifest.save() {
		Ok(_) => {}
		Err(err) => {
			error!("Aborting the account linking process because we failed to save the manifest. This is really bad. Here is the error: {}", err);
			println!(
				"Just in case, here is the account info. Save it somewhere just in case!\n{:?}",
				manifest.get_account(&account_name).unwrap().lock().unwrap()
			);
			return Err(err.into());
		}
	}

	let account_arc = manifest.get_account(&account_name).unwrap();
	let mut account = account_arc.lock().unwrap();

	println!("Authenticator has not yet been linked. Before continuing with finalization, please take the time to write down your revocation code: {}", account.revocation_code);
	tui::pause();

	debug!("attempting link finalization");
	print!("Enter SMS code: ");
	let sms_code = tui::prompt();
	let mut tries = 0;
	loop {
		match linker.finalize(&mut account, sms_code.clone()) {
			Ok(_) => break,
			Err(FinalizeLinkError::WantMore) => {
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

	println!("Authenticator finalized.");
	match manifest.save() {
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
		account.revocation_code
	);

	return Ok(());
}
