extern crate rpassword;
use clap::{crate_version, App, Arg};
use log::*;
use regex::Regex;
use std::collections::HashSet;
use std::{
    io::{stdin, stdout, Write},
    path::Path,
    sync::{Arc, Mutex},
};
use steamguard::{steamapi, Confirmation, ConfirmationType, SteamGuardAccount, UserLogin, LoginError};
use termion::{
    event::{Event, Key},
    input::TermRead,
    raw::IntoRawMode,
    screen::AlternateScreen,
};

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
mod accountlinker;
mod accountmanager;

lazy_static! {
    static ref CAPTCHA_VALID_CHARS: Regex =
        Regex::new("^([A-H]|[J-N]|[P-R]|[T-Z]|[2-4]|[7-9]|[@%&])+$").unwrap();
}

fn main() {
    let matches = App::new("steamguard-cli")
		.version(crate_version!())
		.bin_name("steamguard")
		.author("dyc3 (Carson McManus)")
		.about("Generate Steam 2FA codes and confirm Steam trades from the command line.")
		.arg(
			Arg::with_name("username")
				.long("username")
				.short("u")
				.help("Select the account you want by steam username. By default, the first account in the manifest is selected.")
		)
		.arg(
			Arg::with_name("all")
				.long("all")
				.short("a")
				.takes_value(false)
				.help("Select all accounts in the manifest.")
		)
		.arg(
			Arg::with_name("mafiles-path")
				.long("mafiles-path")
				.short("m")
				.default_value("~/maFiles")
				.help("Specify which folder your maFiles are in.")
		)
		.arg(
			Arg::with_name("passkey")
				.long("passkey")
				.short("p")
				.help("Specify your encryption passkey.")
		)
		.arg(
			Arg::with_name("verbosity")
				.short("v")
				.help("Log what is going on verbosely.")
				.takes_value(false)
				.multiple(true)
		)
		.subcommand(
			App::new("trade")
				.about("Interactive interface for trade confirmations")
				.arg(
					Arg::with_name("accept-all")
					.short("a")
					.long("accept-all")
					.takes_value(false)
					.help("Accept all open trade confirmations. Does not open interactive interface.")
				)
		)
		.subcommand(
			App::new("setup")
			.about("Set up a new account with steamguard-cli")
		)
		.subcommand(
			App::new("debug")
			.arg(
				Arg::with_name("demo-conf-menu")
				.help("Show an example confirmation menu using dummy data.")
				.takes_value(false)
			)
		)
		.get_matches();

    let verbosity = matches.occurrences_of("verbosity") as usize + 2;
    stderrlog::new()
        .verbosity(verbosity)
        .module(module_path!())
        .init()
        .unwrap();

    if let Some(demo_matches) = matches.subcommand_matches("debug") {
        if demo_matches.is_present("demo-conf-menu") {
            demo_confirmation_menu();
        }
        return;
    }

    let path = Path::new(matches.value_of("mafiles-path").unwrap()).join("manifest.json");
    let mut manifest: accountmanager::Manifest;
    match accountmanager::Manifest::load(path.as_path()) {
        Ok(m) => {
            manifest = m;
        }
        Err(e) => {
            error!("Could not load manifest: {}", e);
            return;
        }
    }

    manifest.load_accounts();

    if matches.is_present("setup") {
        info!("setup");
        let mut linker = accountlinker::AccountLinker::new();
        // do_login(&mut linker.account);
        // linker.link(linker.account.session.expect("no login session"));
        return;
    }

    let mut selected_accounts: Vec<Arc<Mutex<SteamGuardAccount>>> = vec![];
    if matches.is_present("all") {
        // manifest.accounts.iter().map(|a| selected_accounts.push(a.b));
        for account in &manifest.accounts {
            selected_accounts.push(account.clone());
        }
    } else {
        for account in &manifest.accounts {
            if !matches.is_present("username") {
                selected_accounts.push(account.clone());
                break;
            }
            if matches.value_of("username").unwrap() == account.lock().unwrap().account_name {
                selected_accounts.push(account.clone());
                break;
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

    if let Some(trade_matches) = matches.subcommand_matches("trade") {
        info!("trade");
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
                        do_login(&mut account);
                    }
                }
            }

            if trade_matches.is_present("accept-all") {
                info!("accepting all confirmations");
                for conf in &confirmations {
                    let result = account.accept_confirmation(conf);
                    debug!("accept confirmation result: {:?}", result);
                }
            } else {
                if termion::is_tty(&stdout()) {
                    let (accept, deny) = prompt_confirmation_menu(confirmations);
                    for conf in &accept {
                        let result = account.accept_confirmation(conf);
                        debug!("accept confirmation result: {:?}", result);
                    }
                    for conf in &deny {
                        let result = account.deny_confirmation(conf);
                        debug!("deny confirmation result: {:?}", result);
                    }
                } else {
                    warn!("not a tty, not showing menu");
                    for conf in &confirmations {
                        println!("{}", conf.description());
                    }
                }
            }
        }

        manifest.save();
    } else {
        let server_time = steamapi::get_server_time();
        for account in selected_accounts {
            trace!("{:?}", account);
            let code = account.lock().unwrap().generate_code(server_time);
            println!("{}", code);
        }
    }
}

fn validate_captcha_text(text: &String) -> bool {
    return CAPTCHA_VALID_CHARS.is_match(text);
}

#[test]
fn test_validate_captcha_text() {
    assert!(validate_captcha_text(&String::from("2WWUA@")));
    assert!(validate_captcha_text(&String::from("3G8HT2")));
    assert!(validate_captcha_text(&String::from("3J%@X3")));
    assert!(validate_captcha_text(&String::from("2GCZ4A")));
    assert!(validate_captcha_text(&String::from("3G8HT2")));
    assert!(!validate_captcha_text(&String::from("asd823")));
    assert!(!validate_captcha_text(&String::from("!PQ4RD")));
    assert!(!validate_captcha_text(&String::from("1GQ4XZ")));
    assert!(!validate_captcha_text(&String::from("8GO4XZ")));
    assert!(!validate_captcha_text(&String::from("IPQ4RD")));
    assert!(!validate_captcha_text(&String::from("0PT4RD")));
    assert!(!validate_captcha_text(&String::from("APTSRD")));
    assert!(!validate_captcha_text(&String::from("AP5TRD")));
    assert!(!validate_captcha_text(&String::from("AP6TRD")));
}

/// Prompt the user for text input.
fn prompt() -> String {
    let mut text = String::new();
    let _ = std::io::stdout().flush();
    stdin()
        .read_line(&mut text)
        .expect("Did not enter a correct string");
    return String::from(text.strip_suffix('\n').unwrap());
}

fn prompt_captcha_text(captcha_gid: &String) -> String {
    println!("Captcha required. Open this link in your web browser: https://steamcommunity.com/public/captcha.php?gid={}", captcha_gid);
    let mut captcha_text;
    loop {
        print!("Enter captcha text: ");
        captcha_text = prompt();
        if captcha_text.len() > 0 && validate_captcha_text(&captcha_text) {
            break;
        }
        warn!("Invalid chars for captcha text found in user's input. Prompting again...");
    }
    return captcha_text;
}

/// Returns a tuple of (accepted, denied). Ignored confirmations are not included.
fn prompt_confirmation_menu(
    confirmations: Vec<Confirmation>,
) -> (Vec<Confirmation>, Vec<Confirmation>) {
    println!("press a key other than enter to show the menu.");
    let mut to_accept_idx: HashSet<usize> = HashSet::new();
    let mut to_deny_idx: HashSet<usize> = HashSet::new();

    let mut screen = AlternateScreen::from(stdout().into_raw_mode().unwrap());
    let stdin = stdin();

    let mut selected_idx = 0;

    for c in stdin.events() {
        match c.expect("could not get events") {
            Event::Key(Key::Char('a')) => {
                to_accept_idx.insert(selected_idx);
                to_deny_idx.remove(&selected_idx);
            }
            Event::Key(Key::Char('d')) => {
                to_accept_idx.remove(&selected_idx);
                to_deny_idx.insert(selected_idx);
            }
            Event::Key(Key::Char('i')) => {
                to_accept_idx.remove(&selected_idx);
                to_deny_idx.remove(&selected_idx);
            }
            Event::Key(Key::Char('A')) => {
                (0..confirmations.len()).for_each(|i| {
                    to_accept_idx.insert(i);
                    to_deny_idx.remove(&i);
                });
            }
            Event::Key(Key::Char('D')) => {
                (0..confirmations.len()).for_each(|i| {
                    to_accept_idx.remove(&i);
                    to_deny_idx.insert(i);
                });
            }
            Event::Key(Key::Char('I')) => {
                (0..confirmations.len()).for_each(|i| {
                    to_accept_idx.remove(&i);
                    to_deny_idx.remove(&i);
                });
            }
            Event::Key(Key::Up) if selected_idx > 0 => {
                selected_idx -= 1;
            }
            Event::Key(Key::Down) if selected_idx < confirmations.len() - 1 => {
                selected_idx += 1;
            }
            Event::Key(Key::Char('\n')) => {
                break;
            }
            Event::Key(Key::Esc) | Event::Key(Key::Ctrl('c')) => {
                return (vec![], vec![]);
            }
            _ => {}
        }

        write!(
            screen,
            "{}{}{}arrow keys to select, [a]ccept, [d]eny, [i]gnore, [enter] confirm choices\n\n",
            termion::clear::All,
            termion::cursor::Goto(1, 1),
            termion::color::Fg(termion::color::White)
        )
        .unwrap();
        for i in 0..confirmations.len() {
            if selected_idx == i {
                write!(
                    screen,
                    "\r{} >",
                    termion::color::Fg(termion::color::LightYellow)
                )
                .unwrap();
            } else {
                write!(screen, "\r{}  ", termion::color::Fg(termion::color::White)).unwrap();
            }

            if to_accept_idx.contains(&i) {
                write!(
                    screen,
                    "{}[a]",
                    termion::color::Fg(termion::color::LightGreen)
                )
                .unwrap();
            } else if to_deny_idx.contains(&i) {
                write!(
                    screen,
                    "{}[d]",
                    termion::color::Fg(termion::color::LightRed)
                )
                .unwrap();
            } else {
                write!(screen, "[ ]").unwrap();
            }

            if selected_idx == i {
                write!(
                    screen,
                    "{}",
                    termion::color::Fg(termion::color::LightYellow)
                )
                .unwrap();
            }

            write!(screen, " {}\n", confirmations[i].description()).unwrap();
        }
    }

    return (
        to_accept_idx.iter().map(|i| confirmations[*i]).collect(),
        to_deny_idx.iter().map(|i| confirmations[*i]).collect(),
    );
}

fn do_login(account: &mut SteamGuardAccount) {
    if account.account_name.len() > 0 {
        println!("Username: {}", account.account_name);
    } else {
        print!("Username: ");
        account.account_name = prompt();
    }
    let _ = std::io::stdout().flush();
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();
    if password.len() > 0 {
        debug!("password is present");
    } else {
        debug!("password is empty");
    }
    // TODO: reprompt if password is empty
    let mut login = UserLogin::new(account.account_name.clone(), password);
    let mut loops = 0;
    loop {
        match login.login() {
            Ok(s) => {
                account.session = Option::Some(s);
                break;
            }
            Err(LoginError::Need2FA) => {
				debug!("generating 2fa code and retrying");
                let server_time = steamapi::get_server_time();
                login.twofactor_code = account.generate_code(server_time);
            }
            Err(LoginError::NeedCaptcha { captcha_gid }) => {
				debug!("need captcha to log in");
                login.captcha_text = prompt_captcha_text(&captcha_gid);
            }
            Err(LoginError::NeedEmail) => {
                println!("You should have received an email with a code.");
                print!("Enter code");
                login.email_code = prompt();
            }
            r => {
                error!("Fatal login result: {:?}", r);
                return;
            }
        }
        loops += 1;
        if loops > 2 {
            error!("Too many loops. Aborting login process, to avoid getting rate limited.");
            return;
        }
    }
}

fn demo_confirmation_menu() {
    info!("showing demo menu");
    let (accept, deny) = prompt_confirmation_menu(vec![
        Confirmation {
            id: 1234,
            key: 12345,
            conf_type: ConfirmationType::Trade,
            creator: 09870987,
        },
        Confirmation {
            id: 1234,
            key: 12345,
            conf_type: ConfirmationType::MarketSell,
            creator: 09870987,
        },
        Confirmation {
            id: 1234,
            key: 12345,
            conf_type: ConfirmationType::AccountRecovery,
            creator: 09870987,
        },
        Confirmation {
            id: 1234,
            key: 12345,
            conf_type: ConfirmationType::Trade,
            creator: 09870987,
        },
    ]);
    println!("accept: {}, deny: {}", accept.len(), deny.len());
}
