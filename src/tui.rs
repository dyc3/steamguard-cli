use crossterm::{
	cursor,
	event::{Event, KeyCode, KeyEvent, KeyModifiers},
	execute,
	style::{Color, Print, PrintStyledContent, SetForegroundColor, Stylize},
	terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
	QueueableCommand,
};
use log::*;
use regex::Regex;
use std::collections::HashSet;
use std::io::{stderr, stdout, Write};
use steamguard::Confirmation;

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
pub(crate) fn prompt() -> String {
	stdout().flush().expect("failed to flush stdout");
	stderr().flush().expect("failed to flush stderr");

	let mut line = String::new();
	while let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
		match code {
			KeyCode::Enter => {
				break;
			}
			KeyCode::Char(c) => {
				line.push(c);
			}
			_ => {}
		}
	}

	line
}

pub(crate) fn prompt_captcha_text(captcha_gid: &String) -> String {
	eprintln!("Captcha required. Open this link in your web browser: https://steamcommunity.com/public/captcha.php?gid={}", captcha_gid);
	let mut captcha_text;
	loop {
		eprint!("Enter captcha text: ");
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
pub(crate) fn prompt_char(text: &str, chars: &str) -> char {
	loop {
		let _ = stderr().queue(Print(format!("{} [{}] ", text, chars)));
		let _ = stderr().flush();
		let input = prompt();
		if let Ok(c) = prompt_char_impl(input, chars) {
			return c;
		}
	}
}

fn prompt_char_impl<T>(input: T, chars: &str) -> anyhow::Result<char>
where
	T: Into<String>,
{
	let uppers = chars.replace(char::is_lowercase, "");
	if uppers.len() > 1 {
		panic!("Invalid chars for prompt_char. Maximum 1 uppercase letter is allowed.");
	}
	let default_answer: Option<char> = if uppers.len() == 1 {
		Some(uppers.chars().collect::<Vec<char>>()[0].to_ascii_lowercase())
	} else {
		None
	};

	let answer: String = input.into().to_ascii_lowercase();

	if answer.len() == 0 {
		if let Some(a) = default_answer {
			return Ok(a);
		} else {
			bail!("no valid answer")
		}
	} else if answer.len() > 1 {
		bail!("answer too long")
	}

	let answer_char = answer.chars().collect::<Vec<char>>()[0];
	if chars.to_ascii_lowercase().contains(answer_char) {
		return Ok(answer_char);
	}

	bail!("no valid answer")
}

/// Returns a tuple of (accepted, denied). Ignored confirmations are not included.
pub(crate) fn prompt_confirmation_menu(
	confirmations: Vec<Confirmation>,
) -> anyhow::Result<(Vec<Confirmation>, Vec<Confirmation>)> {
	if confirmations.len() == 0 {
		bail!("no confirmations")
	}

	let mut to_accept_idx: HashSet<usize> = HashSet::new();
	let mut to_deny_idx: HashSet<usize> = HashSet::new();

	execute!(stdout(), EnterAlternateScreen)?;
	crossterm::terminal::enable_raw_mode()?;

	let mut selected_idx = 0;

	loop {
		execute!(
			stdout(),
			Clear(ClearType::All),
			cursor::MoveTo(1, 1),
			PrintStyledContent(
				"arrow keys to select, [a]ccept, [d]eny, [i]gnore, [enter] confirm choices\n\n"
					.white()
			),
		)?;

		for i in 0..confirmations.len() {
			stdout().queue(Print("\r"))?;
			if selected_idx == i {
				stdout().queue(SetForegroundColor(Color::Yellow))?;
				stdout().queue(Print(" >"))?;
			} else {
				stdout().queue(SetForegroundColor(Color::White))?;
				stdout().queue(Print("  "))?;
			}

			if to_accept_idx.contains(&i) {
				stdout().queue(SetForegroundColor(Color::Green))?;
				stdout().queue(Print("[a]"))?;
			} else if to_deny_idx.contains(&i) {
				stdout().queue(SetForegroundColor(Color::Red))?;
				stdout().queue(Print("[d]"))?;
			} else {
				stdout().queue(Print("[ ]"))?;
			}

			if selected_idx == i {
				stdout().queue(SetForegroundColor(Color::Yellow))?;
			}

			stdout().queue(Print(format!(" {}\n", confirmations[i].description())))?;
		}

		stdout().flush()?;

		match crossterm::event::read()? {
			Event::Resize(_, _) => continue,
			Event::Key(KeyEvent {
				code: KeyCode::Char('a'),
				..
			}) => {
				to_accept_idx.insert(selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('d'),
				..
			}) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.insert(selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('i'),
				..
			}) => {
				to_accept_idx.remove(&selected_idx);
				to_deny_idx.remove(&selected_idx);
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('A'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.insert(i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('D'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.insert(i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Char('I'),
				..
			}) => {
				(0..confirmations.len()).for_each(|i| {
					to_accept_idx.remove(&i);
					to_deny_idx.remove(&i);
				});
			}
			Event::Key(KeyEvent {
				code: KeyCode::Up, ..
			}) if selected_idx > 0 => {
				selected_idx -= 1;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Down,
				..
			}) if selected_idx < confirmations.len() - 1 => {
				selected_idx += 1;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Enter,
				..
			}) => {
				break;
			}
			Event::Key(KeyEvent {
				code: KeyCode::Esc, ..
			})
			| Event::Key(KeyEvent {
				code: KeyCode::Char('c'),
				modifiers: KeyModifiers::CONTROL,
			}) => {
				return Ok((vec![], vec![]));
			}
			_ => {}
		}
	}

	execute!(stdout(), LeaveAlternateScreen)?;
	crossterm::terminal::disable_raw_mode()?;

	return Ok((
		to_accept_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
		to_deny_idx
			.iter()
			.map(|i| confirmations[*i].clone())
			.collect(),
	));
}

pub(crate) fn pause() {
	let _ = write!(stderr(), "Press enter to continue...");
	let _ = stderr().flush();
	loop {
		match crossterm::event::read().expect("could not read terminal events") {
			Event::Key(KeyEvent {
				code: KeyCode::Enter,
				..
			}) => break,
			_ => continue,
		}
	}
}

#[cfg(test)]
mod prompt_char_tests {
	use super::*;

	#[test]
	fn test_gives_answer() {
		let answer = prompt_char_impl("y", "yn").unwrap();
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_gives_default() {
		let answer = prompt_char_impl("", "Yn").unwrap();
		assert_eq!(answer, 'y');
	}

	#[test]
	fn test_should_not_give_default() {
		let answer = prompt_char_impl("n", "Yn").unwrap();
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_invalid() {
		let answer = prompt_char_impl("g", "yn");
		assert!(matches!(answer, Err(_)));
		let answer = prompt_char_impl("n", "yn").unwrap();
		assert_eq!(answer, 'n');
	}

	#[test]
	fn test_should_not_give_multichar() {
		let answer = prompt_char_impl("yy", "yn");
		assert!(matches!(answer, Err(_)));
	}
}
