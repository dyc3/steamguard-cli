use std::sync::{Arc, Mutex};

use clap::Parser;
use gpui::{
	div, prelude::*, px, rgb, size, App, Application, Bounds, ClipboardItem, Context, Entity,
	Window, WindowBounds, WindowOptions,
};
use secrecy::SecretString;
use steamguard::{
	approver::Challenge, protobufs::enums::ESessionPersistence, steamapi, transport::Transport,
	ApproverError, ConfirmationId, Confirmer, ConfirmerError, LoginApprover, SteamGuardAccount,
};

use crate::AccountManager;

use super::*;

#[derive(Debug, Clone, Parser)]
#[clap(about = "Launch a GUI for account codes, confirmations, and approvals")]
pub struct GuiCommand {}

#[derive(Debug, Clone)]
struct PendingConfirmation {
	id: String,
	nonce: String,
	description: String,
}

#[derive(Debug, Clone)]
struct PendingApproval {
	client_id: u64,
	description: String,
}

struct GuiView<T>
where
	T: Transport + Clone + 'static,
{
	transport: T,
	accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
	selected_account_idx: usize,
	code: String,
	confirmations: Vec<PendingConfirmation>,
	approvals: Vec<PendingApproval>,
	status: String,
	password: Option<SecretString>,
}

impl<T> GuiView<T>
where
	T: Transport + Clone + 'static,
{
	fn new(
		transport: T,
		accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
		password: Option<SecretString>,
		selected_account_idx: usize,
	) -> Self {
		let selected_account_idx = selected_account_idx.min(accounts.len().saturating_sub(1));
		let mut this = Self {
			transport,
			accounts,
			selected_account_idx,
			code: String::new(),
			confirmations: vec![],
			approvals: vec![],
			status: String::new(),
			password,
		};
		this.refresh_code();
		this
	}

	fn selected_account(&self) -> anyhow::Result<Arc<Mutex<SteamGuardAccount>>> {
		self.accounts
			.get(self.selected_account_idx)
			.cloned()
			.ok_or_else(|| anyhow!("No selected account"))
	}

	fn selected_account_name(&self) -> String {
		self.selected_account()
			.and_then(|account| {
				let account = account
					.lock()
					.map_err(|_| anyhow!("account lock poisoned"))?;
				Ok(account.account_name.clone())
			})
			.unwrap_or_else(|_| "Unknown account".to_string())
	}

	fn set_status(&mut self, message: impl Into<String>) {
		self.status = message.into();
	}

	fn select_account(&mut self, idx: usize) {
		if idx >= self.accounts.len() {
			return;
		}
		self.selected_account_idx = idx;
		self.confirmations.clear();
		self.approvals.clear();
		self.refresh_code();
		self.set_status(format!("Selected {}", self.selected_account_name()));
	}

	fn ensure_logged_in(&mut self, account: &mut SteamGuardAccount) -> anyhow::Result<()> {
		if account.is_logged_in() {
			return Ok(());
		}
		crate::do_login(self.transport.clone(), account, self.password.clone())
	}

	fn refresh_code(&mut self) {
		let result = (|| -> anyhow::Result<String> {
			let server_time = steamapi::get_server_time(self.transport.clone())?.server_time();
			let account = self.selected_account()?;
			let account = account
				.lock()
				.map_err(|_| anyhow!("account lock poisoned"))?;
			Ok(account.generate_code(server_time))
		})();

		match result {
			Ok(code) => {
				self.code = code;
			}
			Err(err) => {
				self.code = "------".to_string();
				self.set_status(format!("Failed to refresh code: {}", err));
			}
		}
	}

	fn refresh_confirmations(&mut self) {
		let result = (|| -> anyhow::Result<Vec<PendingConfirmation>> {
			let selected = self.selected_account()?;
			let mut account = selected
				.lock()
				.map_err(|_| anyhow!("account lock poisoned"))?;
			let mut did_relogin = false;

			loop {
				self.ensure_logged_in(&mut account)?;
				let confirmer = Confirmer::new(self.transport.clone(), &account);
				match confirmer.get_confirmations() {
					Ok(confirmations) => {
						return Ok(confirmations
							.into_iter()
							.map(|confirmation| {
								let description = confirmation.description();
								PendingConfirmation {
									id: confirmation.id,
									nonce: confirmation.nonce,
									description,
								}
							})
							.collect());
					}
					Err(ConfirmerError::InvalidTokens) if !did_relogin => {
						did_relogin = true;
						account.tokens = None;
					}
					Err(err) => return Err(err.into()),
				}
			}
		})();

		match result {
			Ok(confirmations) => {
				let count = confirmations.len();
				self.confirmations = confirmations;
				self.set_status(format!("Fetched {} mobile confirmations", count));
			}
			Err(err) => {
				self.confirmations.clear();
				self.set_status(format!("Failed to fetch confirmations: {}", err));
			}
		}
	}

	fn respond_confirmation(&mut self, idx: usize, accept: bool) {
		if idx >= self.confirmations.len() {
			return;
		}

		let pending = self.confirmations[idx].clone();
		let result = (|| -> anyhow::Result<()> {
			let selected = self.selected_account()?;
			let mut account = selected
				.lock()
				.map_err(|_| anyhow!("account lock poisoned"))?;
			let mut did_relogin = false;

			loop {
				self.ensure_logged_in(&mut account)?;
				let confirmer = Confirmer::new(self.transport.clone(), &account);
				let id = ConfirmationId::new(&pending.id, &pending.nonce);
				let response = if accept {
					confirmer.accept_confirmation(id)
				} else {
					confirmer.deny_confirmation(id)
				};
				match response {
					Ok(()) => break,
					Err(ConfirmerError::InvalidTokens) if !did_relogin => {
						did_relogin = true;
						account.tokens = None;
					}
					Err(err) => return Err(err.into()),
				}
			}
			Ok(())
		})();

		match result {
			Ok(_) => {
				self.confirmations.remove(idx);
				let action = if accept { "accepted" } else { "denied" };
				self.set_status(format!("{} confirmation {}", action, pending.id));
			}
			Err(err) => {
				self.set_status(format!("Failed to respond to confirmation: {}", err));
			}
		}
	}

	fn refresh_approvals(&mut self) {
		let result = (|| -> anyhow::Result<Vec<PendingApproval>> {
			let selected = self.selected_account()?;
			let mut account = selected
				.lock()
				.map_err(|_| anyhow!("account lock poisoned"))?;
			let mut did_relogin = false;

			let (sessions, approver) = loop {
				self.ensure_logged_in(&mut account)?;
				let Some(tokens) = account.tokens.as_ref() else {
					return Err(anyhow!("No login tokens for selected account"));
				};
				let approver = LoginApprover::new(self.transport.clone(), tokens);
				match approver.list_auth_sessions() {
					Ok(sessions) => break (sessions, approver),
					Err(ApproverError::Unauthorized) if !did_relogin => {
						did_relogin = true;
						account.tokens = None;
					}
					Err(err) => return Err(err.into()),
				}
			};

			let mut pending = Vec::with_capacity(sessions.len());
			for client_id in sessions {
				let session = approver.get_auth_session_info(client_id)?;
				let description = format!(
					"{} | {} | {}",
					session.ip(),
					session.country(),
					session.device_friendly_name()
				);
				pending.push(PendingApproval {
					client_id,
					description,
				});
			}

			Ok(pending)
		})();

		match result {
			Ok(approvals) => {
				let count = approvals.len();
				self.approvals = approvals;
				self.set_status(format!("Fetched {} login approvals", count));
			}
			Err(err) => {
				self.approvals.clear();
				self.set_status(format!("Failed to fetch login approvals: {}", err));
			}
		}
	}

	fn respond_approval(&mut self, idx: usize, approve: bool) {
		if idx >= self.approvals.len() {
			return;
		}

		let pending = self.approvals[idx].clone();
		let result = (|| -> anyhow::Result<()> {
			let selected = self.selected_account()?;
			let mut account = selected
				.lock()
				.map_err(|_| anyhow!("account lock poisoned"))?;
			let mut did_relogin = false;

			loop {
				self.ensure_logged_in(&mut account)?;
				let tokens = account
					.tokens
					.as_ref()
					.ok_or_else(|| anyhow!("No login tokens for selected account"))?;
				let mut approver = LoginApprover::new(self.transport.clone(), tokens);
				let challenge = Challenge::new(1, pending.client_id);
				let response = if approve {
					approver.approve(
						&account,
						challenge,
						ESessionPersistence::k_ESessionPersistence_Persistent,
					)
				} else {
					approver.deny(&account, challenge)
				};

				match response {
					Ok(()) => break,
					Err(ApproverError::Unauthorized) if !did_relogin => {
						did_relogin = true;
						account.tokens = None;
					}
					Err(err) => return Err(err.into()),
				}
			}
			Ok(())
		})();

		match result {
			Ok(_) => {
				self.approvals.remove(idx);
				let action = if approve { "Approved" } else { "Denied" };
				self.set_status(format!("{} login session {}", action, pending.client_id));
			}
			Err(err) => {
				self.set_status(format!("Failed to respond to login approval: {}", err));
			}
		}
	}
}

impl<T> Render for GuiView<T>
where
	T: Transport + Clone + 'static,
{
	fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
		let entity: Entity<Self> = cx.entity();

		div()
			.size_full()
			.bg(rgb(0x111827))
			.text_color(rgb(0xE5E7EB))
			.font_family("monospace")
			.p_4()
			.gap_4()
			.flex()
			.child(
				div()
					.w(px(220.0))
					.flex_none()
					.gap_2()
					.flex()
					.flex_col()
					.child(div().text_sm().text_color(rgb(0x9CA3AF)).child("Accounts"))
					.children(self.accounts.iter().enumerate().map(|(idx, account)| {
						let account_name = account
							.lock()
							.map(|account| account.account_name.clone())
							.unwrap_or_else(|_| "<unavailable>".to_string());
						let view = entity.clone();
						div()
							.id(("account", idx))
							.px_2()
							.py_1()
							.rounded_md()
							.cursor_pointer()
							.bg(if idx == self.selected_account_idx {
								rgb(0x2563EB)
							} else {
								rgb(0x1F2937)
							})
							.hover(|style| style.bg(rgb(0x374151)))
							.on_click(move |_, _, app| {
								view.update(app, |view, cx| {
									view.select_account(idx);
									cx.notify();
								});
							})
							.child(account_name)
					})),
			)
			.child(
				div()
					.flex_1()
					.gap_4()
					.flex()
					.flex_col()
					.child(
						div()
							.gap_2()
							.flex()
							.flex_col()
							.child(
								div()
									.flex()
									.justify_between()
									.items_center()
									.child(div().text_sm().text_color(rgb(0x9CA3AF)).child(
										format!("2FA code for {}", self.selected_account_name()),
									))
									.child(
										div()
											.flex()
											.gap_2()
											.child(
												div()
													.id(("refresh-code", 0usize))
													.cursor_pointer()
													.px_2()
													.py_1()
													.rounded_md()
													.bg(rgb(0x334155))
													.child("Refresh")
													.on_click({
														let view = entity.clone();
														move |_, _, app| {
															view.update(app, |view, cx| {
																view.refresh_code();
																cx.notify();
															});
														}
													}),
											)
											.child(
												div()
													.id(("copy-code", 0usize))
													.cursor_pointer()
													.px_2()
													.py_1()
													.rounded_md()
													.bg(rgb(0x0F766E))
													.child("Copy")
													.on_click({
														let view = entity.clone();
														move |_, _, app| {
															view.update(app, |view, cx| {
																cx.write_to_clipboard(
																	ClipboardItem::new_string(
																		view.code.clone(),
																	),
																);
																view.set_status(
																	"Copied 2FA code to clipboard",
																);
																cx.notify();
															});
														}
													}),
											),
									),
							)
							.child(
								div()
									.px_3()
									.py_2()
									.rounded_md()
									.bg(rgb(0x0B1220))
									.border_1()
									.border_color(rgb(0x334155))
									.text_size(px(28.0))
									.child(self.code.clone()),
							),
					)
					.child(
						div()
							.gap_2()
							.flex()
							.flex_col()
							.child(
								div()
									.flex()
									.justify_between()
									.items_center()
									.child(
										div()
											.text_sm()
											.text_color(rgb(0x9CA3AF))
											.child("Mobile confirmations"),
									)
									.child(
										div()
											.id(("fetch-confirmations", 0usize))
											.cursor_pointer()
											.px_2()
											.py_1()
											.rounded_md()
											.bg(rgb(0x334155))
											.child("Fetch")
											.on_click({
												let view = entity.clone();
												move |_, _, app| {
													view.update(app, |view, cx| {
														view.refresh_confirmations();
														cx.notify();
													});
												}
											}),
									),
							)
							.child(if self.confirmations.is_empty() {
								div()
									.text_color(rgb(0x9CA3AF))
									.child("No pending confirmations")
							} else {
								div().gap_2().flex().flex_col().children(
									self.confirmations.iter().enumerate().map(
										|(idx, confirmation)| {
											div()
												.id(("confirmation", idx))
												.flex()
												.justify_between()
												.gap_2()
												.items_center()
												.p_2()
												.rounded_md()
												.bg(rgb(0x1F2937))
												.child(
													div()
														.flex_1()
														.child(confirmation.description.clone()),
												)
												.child(
													div()
														.flex()
														.gap_2()
														.child(
															div()
																.id(("accept-confirmation", idx))
																.cursor_pointer()
																.px_2()
																.py_1()
																.rounded_md()
																.bg(rgb(0x166534))
																.child("Accept")
																.on_click({
																	let view = entity.clone();
																	move |_, _, app| {
																		view.update(
																			app,
																			|view, cx| {
																				view.respond_confirmation(idx, true);
																				cx.notify();
																			},
																		);
																	}
																}),
														)
														.child(
															div()
																.id(("deny-confirmation", idx))
																.cursor_pointer()
																.px_2()
																.py_1()
																.rounded_md()
																.bg(rgb(0x991B1B))
																.child("Deny")
																.on_click({
																	let view = entity.clone();
																	move |_, _, app| {
																		view.update(
																			app,
																			|view, cx| {
																				view.respond_confirmation(idx, false);
																				cx.notify();
																			},
																		);
																	}
																}),
														),
												)
										},
									),
								)
							}),
					)
					.child(
						div()
							.gap_2()
							.flex()
							.flex_col()
							.child(
								div()
									.flex()
									.justify_between()
									.items_center()
									.child(
										div()
											.text_sm()
											.text_color(rgb(0x9CA3AF))
											.child("Login approvals"),
									)
									.child(
										div()
											.id(("fetch-approvals", 0usize))
											.cursor_pointer()
											.px_2()
											.py_1()
											.rounded_md()
											.bg(rgb(0x334155))
											.child("Fetch")
											.on_click({
												let view = entity.clone();
												move |_, _, app| {
													view.update(app, |view, cx| {
														view.refresh_approvals();
														cx.notify();
													});
												}
											}),
									),
							)
							.child(if self.approvals.is_empty() {
								div()
									.text_color(rgb(0x9CA3AF))
									.child("No pending login approvals")
							} else {
								div().gap_2().flex().flex_col().children(
									self.approvals.iter().enumerate().map(|(idx, approval)| {
										div()
											.id(("approval", idx))
											.flex()
											.justify_between()
											.gap_2()
											.items_center()
											.p_2()
											.rounded_md()
											.bg(rgb(0x1F2937))
											.child(
												div().flex_1().child(approval.description.clone()),
											)
											.child(
												div()
													.flex()
													.gap_2()
													.child(
														div()
															.id(("approve-login", idx))
															.cursor_pointer()
															.px_2()
															.py_1()
															.rounded_md()
															.bg(rgb(0x166534))
															.child("Approve")
															.on_click({
																let view = entity.clone();
																move |_, _, app| {
																	view.update(app, |view, cx| {
																		view.respond_approval(
																			idx, true,
																		);
																		cx.notify();
																	});
																}
															}),
													)
													.child(
														div()
															.id(("deny-login", idx))
															.cursor_pointer()
															.px_2()
															.py_1()
															.rounded_md()
															.bg(rgb(0x991B1B))
															.child("Deny")
															.on_click({
																let view = entity.clone();
																move |_, _, app| {
																	view.update(app, |view, cx| {
																		view.respond_approval(
																			idx, false,
																		);
																		cx.notify();
																	});
																}
															}),
													),
											)
									}),
								)
							}),
					)
					.child(
						div()
							.mt_2()
							.px_2()
							.py_1()
							.rounded_md()
							.bg(rgb(0x0F172A))
							.text_sm()
							.text_color(rgb(0x93C5FD))
							.child(self.status.clone()),
					),
			)
	}
}

impl<T> ManifestCommand<T> for GuiCommand
where
	T: Transport + Clone + 'static,
{
	fn execute(
		&self,
		transport: T,
		manager: &mut AccountManager,
		args: &GlobalArgs,
	) -> anyhow::Result<()> {
		if manager.iter().next().is_none() {
			bail!("No accounts found in manifest");
		}

		manager.load_accounts()?;
		let password = args.password.clone();
		let account_names: Vec<String> = manager
			.iter()
			.map(|entry| entry.account_name.clone())
			.collect();
		let selected_account_idx = if let Some(username) = &args.username {
			account_names
				.iter()
				.position(|account_name| account_name == username)
				.ok_or_else(|| anyhow!("Account '{}' not found in manifest", username))?
		} else {
			0
		};
		let mut accounts = Vec::new();
		for account_name in account_names {
			accounts.push(manager.get_or_load_account(&account_name)?);
		}

		let startup_error = Arc::new(Mutex::new(None::<String>));
		let startup_error_inner = startup_error.clone();
		Application::new().run(move |cx: &mut App| {
			let bounds = Bounds::centered(None, size(px(980.0), px(700.0)), cx);
			if let Err(err) = cx.open_window(
				WindowOptions {
					window_bounds: Some(WindowBounds::Windowed(bounds)),
					..Default::default()
				},
				|_, cx| {
					cx.new(|_| GuiView::new(transport, accounts, password, selected_account_idx))
				},
			) {
				*startup_error_inner
					.lock()
					.expect("failed to lock startup error") = Some(err.to_string());
				cx.quit();
				return;
			}
			cx.activate(true);
		});

		if let Some(err) = startup_error
			.lock()
			.expect("failed to lock startup error")
			.take()
		{
			bail!("Failed to open GUI window: {}", err);
		}

		manager.save()?;
		Ok(())
	}
}
