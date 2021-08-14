use log::*;
use regex::Regex;
use std::collections::HashSet;
use std::io::{Read, Write};
use steamguard::Confirmation;
use termion::{
	event::{Event, Key},
	input::TermRead,
	raw::IntoRawMode,
	screen::AlternateScreen,
};

lazy_static! {
	static ref CAPTCHA_VALID_CHARS: Regex =
		Regex::new("^([A-H]|[J-N]|[P-R]|[T-Z]|[2-4]|[7-9]|[@%&])+$").unwrap();
}

pub fn validate_captcha_text(text: &String) -> bool {
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
pub fn prompt() -> String {
	let mut text = String::new();
	let _ = std::io::stdout().flush();
	std::io::stdin()
		.read_line(&mut text)
		.expect("Did not enter a correct string");
	return String::from(text.strip_suffix('\n').unwrap());
}

pub fn prompt_captcha_text(captcha_gid: &String) -> String {
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

/// Prompt the user for a single character response. Useful for asking yes or no questions.
///
/// `chars` should be all lowercase characters, with at most 1 uppercase character. The uppercase character is the default answer if no answer is provided.
pub fn prompt_char(text: &str, chars: &str) -> char {
	return prompt_char_impl(&mut std::io::stdin(), text, chars);
}

fn prompt_char_impl(input: &mut impl Read, text: &str, chars: &str) -> char {
	let uppers = chars.replace(char::is_lowercase, "");
	if uppers.len() > 1 {
		panic!("Invalid chars for prompt_char. Maximum 1 uppercase letter is allowed.");
	}
	let default_answer: Option<char> = if uppers.len() == 1 {
		Some(uppers.chars().collect::<Vec<char>>()[0].to_ascii_lowercase())
	} else {
		None
	};

	loop {
		print!("{} [{}] ", text, chars);
		let answer = input
			.read_line()
			.expect("Unable to read input")
			.unwrap()
			.to_ascii_lowercase();
		if answer.len() == 0 {
			if let Some(a) = default_answer {
				return a;
			}
		} else if answer.len() > 1 {
			continue;
		}

		let answer_char = answer.chars().collect::<Vec<char>>()[0];
		if chars.contains(answer_char) {
			return answer_char;
		}
	}
}

/// Returns a tuple of (accepted, denied). Ignored confirmations are not included.
pub fn prompt_confirmation_menu(
	confirmations: Vec<Confirmation>,
) -> (Vec<Confirmation>, Vec<Confirmation>) {
	println!("press a key other than enter to show the menu.");
	let mut to_accept_idx: HashSet<usize> = HashSet::new();
	let mut to_deny_idx: HashSet<usize> = HashSet::new();

	let mut screen = AlternateScreen::from(std::io::stdout().into_raw_mode().unwrap());
	let stdin = std::io::stdin();

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
		to_accept_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
		to_deny_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
	);
}

pub fn pause() {
	println!("Press any key to continue...");
	let mut stdout = std::io::stdout().into_raw_mode().unwrap();
	stdout.flush().unwrap();
	std::io::stdin().events().next();
}

#[cfg(test)]
mod prompt_char_tests {
	use super::*;

	#[test]
	fn test_gives_answer() {
		let inputs = ['y', '\n'].iter().collect::<String>();
		let answer = prompt_char_impl(&mut inputs.as_bytes(), "ligma balls", "yn");
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_gives_default() {
		let inputs = ['\n'].iter().collect::<String>();
		let answer = prompt_char_impl(&mut inputs.as_bytes(), "ligma balls", "Yn");
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_should_not_give_default() {
		let inputs = ['n', '\n'].iter().collect::<String>();
		let answer = prompt_char_impl(&mut inputs.as_bytes(), "ligma balls", "Yn");
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_invalid() {
		let inputs = ['g', '\n', 'n', '\n'].iter().collect::<String>();
		let answer = prompt_char_impl(&mut inputs.as_bytes(), "ligma balls", "yn");
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_multichar() {
		let inputs = ['y', 'y', '\n', 'n', '\n'].iter().collect::<String>();
		let answer = prompt_char_impl(&mut inputs.as_bytes(), "ligma balls", "yn");
		assert_eq!(answer, 'n');
	}
}
