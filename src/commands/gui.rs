use std::collections::HashMap;

use log::*;

use secrecy::ExposeSecret;
use steamguard::{
	api_responses::AllowedConfirmation,
	protobufs::steammessages_auth_steamclient::{
		CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response, EAuthSessionGuardType,
	},
	refresher::TokenRefresher,
	steamapi::AuthenticationClient,
	userlogin::UpdateAuthSessionError,
	Confirmation, Confirmer, ConfirmerError, LoginError, UserLogin,
};

use super::*;

#[derive(Debug, Clone, Parser, Default)]
pub struct GuiCommand;

impl GuiCommand {
	pub(crate) fn execute<T>(
		self,
		transport: T,
		manager: AccountManager,
		args: &GlobalArgs,
	) -> anyhow::Result<()>
	where
		T: Transport + Clone + Send + 'static,
	{
		info!("Starting GUI");

		let native_options = eframe::NativeOptions {
			initial_window_size: Some([400.0, 300.0].into()),
			min_window_size: Some([300.0, 220.0].into()),
			..Default::default()
		};
		let args = args.clone();
		if let Err(e) = eframe::run_native(
			"steamguard",
			native_options,
			Box::new(|cc| Box::new(Gui::new(cc, transport, manager, self, args))),
		) {
			error!("Failed to start gui: {}", e);
		}

		Ok(())
	}
}

struct Gui<T: Transport + Clone + Send + 'static> {
	transport: T,
	manager: AccountManager,
	_args: GuiCommand,
	_globalargs: GlobalArgs,

	selected_account: usize,
	confirmations: HashMap<usize, Result<Vec<Confirmation>, ConfirmerError>>,
	login_state: LoginState,
	just_switched_account: bool,

	confirmations_job: ThreadJob<Result<Vec<Confirmation>, ConfirmerError>>,
	refresh_tokens_job: ThreadJob<anyhow::Result<()>>,
	login_begin_job: ThreadJob<Result<Vec<AllowedConfirmation>, LoginError>>,
	login_begin_result: Option<Result<Vec<AllowedConfirmation>, LoginError>>,
	login_confirm_job: ThreadJob<
		anyhow::Result<
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response,
			UpdateAuthSessionError,
		>,
	>,
	login_confirm_result: Option<
		anyhow::Result<
			CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response,
			UpdateAuthSessionError,
		>,
	>,
	login_poll_job: ThreadJob<anyhow::Result<()>>,
	/// The password used to log in to the currently selected account.
	///
	/// TODO: make this [`SecretString`] somehow
	login_password: String,
	login_confirm_code: String,
	user_login: Option<Arc<Mutex<UserLogin<T>>>>,
}

impl<T: Transport + Clone + Send + 'static> Gui<T> {
	fn new(
		_ctx: &eframe::CreationContext<'_>,
		transport: T,
		manager: AccountManager,
		args: GuiCommand,
		globalargs: GlobalArgs,
	) -> Self {
		Self {
			transport,
			manager,
			_args: args,
			_globalargs: globalargs,

			selected_account: Default::default(),
			confirmations: Default::default(),
			login_state: LoginState::Unknown,
			just_switched_account: true,

			confirmations_job: ThreadJob::new(),
			refresh_tokens_job: ThreadJob::new(),
			login_begin_job: ThreadJob::new(),
			login_begin_result: Default::default(),
			login_confirm_job: ThreadJob::new(),
			login_confirm_result: Default::default(),
			login_poll_job: ThreadJob::new(),
			login_password: Default::default(),
			login_confirm_code: Default::default(),
			user_login: None,
		}
	}
}

impl<T> eframe::App for Gui<T>
where
	T: Transport + Clone + Send + 'static,
{
	fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
		egui::CentralPanel::default().show(ctx, |ui| {
			let mut selected_account_name = self
				.manager
				.iter()
				.nth(self.selected_account)
				.unwrap()
				.account_name
				.clone();
			egui::ComboBox::from_label("Account")
				.selected_text(&selected_account_name)
				.show_ui(ui, |ui| {
					for (i, entry) in self.manager.iter().enumerate() {
						let selectable = ui.selectable_value(
							&mut self.selected_account,
							i,
							entry.account_name.clone(),
						);
						if selectable.clicked() {
							debug!("Selected account {}", entry.account_name);
							self.just_switched_account = true;
							selected_account_name = entry.account_name.clone();
						}
					}
				});

			let account = self
				.manager
				.get_or_load_account(&selected_account_name)
				.unwrap();

			if self.just_switched_account {
				self.just_switched_account = false;
				self.login_state = LoginState::Unknown;
				self.confirmations_job = ThreadJob::new();
				self.refresh_tokens_job = ThreadJob::new();
				self.login_begin_job = ThreadJob::new();
			}

			let mut code = account.read().unwrap().generate_code(
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			);

			egui::TextEdit::singleline(&mut code)
				.interactive(false)
				.show(ui);

			ui.label(format!("Login State: {:?}", self.login_state));

			ui.add(egui::Separator::default());

			match self.login_state {
				LoginState::Unknown => {
					let account = account.read().unwrap();
					debug!("Determining login state for {}", account.account_name);
					if let Some(tokens) = account.tokens.as_ref() {
						let expired_or_invalid = match tokens.access_token().decode() {
							Ok(data) => data.is_expired(),
							Err(_) => true,
						};
						if expired_or_invalid {
							self.login_state = LoginState::NeedsRefresh;
						} else {
							self.login_state = LoginState::HasAuth;
						}
					} else {
						self.login_state = LoginState::NeedsLogin;
					}
					debug!("Login state determined: {:?}", self.login_state);
				}
				LoginState::HasAuth => {}
				LoginState::NeedsLogin => {
					ui.label("Please log in");

					ui.vertical(|ui| {
						ui.horizontal(|ui| {
							ui.label("Username:");
							egui::TextEdit::singleline(&mut selected_account_name)
								.interactive(false)
								.show(ui);
						});
						ui.horizontal(|ui| {
							ui.label("Password:");

							let txt_password =
								egui::TextEdit::singleline(&mut self.login_password).password(true);
							ui.add(txt_password);
						});
						if ui.button("Login").clicked() {
							let transport = self.transport.clone();
							let account = account.clone();
							let ctx = ctx.clone();
							let user_login = self
								.user_login
								.get_or_insert_with(|| {
									Arc::new(Mutex::new(UserLogin::new(
										transport.clone(),
										crate::login::build_device_details(),
									)))
								})
								.clone();
							let password =
								SecretString::new(std::mem::take(&mut self.login_password));

							self.login_begin_job.start(move || {
								let result = job_begin_login(user_login, account, password);
								ctx.request_repaint();
								result
							});
						}
					});

					match self.login_begin_job.status() {
						JobStatus::NotStarted => {}
						JobStatus::InProgress => {
							ui.horizontal(|ui| {
								ui.spinner();
								ui.label("Logging in...");
							});
						}
						JobStatus::Finished => {
							debug!("login begin job finished");
							self.login_begin_result = Some(self.login_begin_job.result());
						}
					}
					if let Some(result) = self.login_begin_result.as_ref() {
						match result {
							Ok(_) => {
								self.login_state = LoginState::NeedsConfirmation;
							}
							Err(e) => {
								self.login_state = LoginState::NeedsLogin;
								ui.label(format!("Error: {}", e));
							}
						}
					}
				}
				LoginState::NeedsConfirmation => {
					let Some(user_login) = self.user_login.as_ref() else {
						self.login_state = LoginState::NeedsLogin;
						return;
					};

					let mut confirmation_method = None;

					if let Ok(confirmation_methods) = self.login_begin_result.as_ref().unwrap() {
						if !confirmation_methods.is_empty() {
							ui.label("Please confirm login");
						}
						for method in confirmation_methods {
							match method.confirmation_type {
								EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceConfirmation => {
									ui.label("Please confirm this login on your other device.");
								}
								EAuthSessionGuardType::k_EAuthSessionGuardType_EmailConfirmation => {
									ui.label(
										"Please confirm this login by clicking the link in your email."
									);
									if !method.associated_messsage.is_empty() {
										ui.label(format!(" ({})", method.associated_messsage));
									}
								}
								EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode => {
									debug!("Generating 2fa code...");
									let time = std::time::SystemTime::now()
										.duration_since(std::time::UNIX_EPOCH)
										.unwrap()
										.as_secs();
									self.login_confirm_code = account.read().unwrap().generate_code(time);
								}
								EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {
									ui.label("Enter the 2fa code sent to your email: ");
									egui::TextEdit::singleline(&mut self.login_confirm_code).show(ui);
								}
								_ => {
									ui.label(format!("Warning: Unknown confirmation method: {:?}", method));
									continue;
								}
							}
							confirmation_method = Some(method);
							break;
						}
					}

					let Some(confirmation_method) = confirmation_method else {
						error!("No known confirmation methods");
						self.login_state = LoginState::NeedsLogin;
						return;
					};

					// ui.label(format!("Confirmation method: {:?}", confirmation_method.confirmation_type));

					match confirmation_method.confirmation_type {
						EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode | EAuthSessionGuardType::k_EAuthSessionGuardType_EmailCode => {

						match self.login_confirm_job.status() {
							JobStatus::NotStarted => {
									if ui.button("Submit").clicked() || confirmation_method.confirmation_type == EAuthSessionGuardType::k_EAuthSessionGuardType_DeviceCode {
										let user_login = user_login.clone();
										let guard_type = confirmation_method.confirmation_type;
										let code = self.login_confirm_code.clone();
										let ctx = ctx.clone();
										self.login_confirm_job.start(move || {
											let result = job_login_submit_code(user_login, guard_type, code);
											ctx.request_repaint();
											result
										});
										}
									}
								JobStatus::InProgress => {
									ui.horizontal(|ui| {
										ui.spinner();
										ui.label("Confirming...");
									});
								}
								JobStatus::Finished => {
									debug!("login confirm job finished");
									self.login_confirm_result = Some(self.login_confirm_job.result());
								}
							}
							if let Some(result) = self.login_confirm_result.as_ref() {
								match result {
									Ok(_) => {
										self.login_state = LoginState::WaitingForTokens;
									}
									Err(e) => {
										self.login_state = LoginState::NeedsLogin;
										ui.label(format!("Error: {}", e));
									}
								}
							}
						},
						_ => {}
					}
				}
				LoginState::WaitingForTokens => {
					let Some(user_login) = self.user_login.as_ref() else {
						self.login_state = LoginState::NeedsLogin;
						return;
					};

					match self.login_poll_job.status() {
						JobStatus::NotStarted => {
							let user_login = user_login.clone();
							let account = account.clone();
							let ctx = ctx.clone();
							self.login_poll_job.start(move || {
								let result = job_login_poll_tokens(user_login, account);
								ctx.request_repaint();
								result
							});
						},
						JobStatus::InProgress => {
							ui.horizontal(|ui| {
								ui.spinner();
								ui.label("Waiting for tokens...");
							});
						},
						JobStatus::Finished => {
							if let Err(e) = self.manager.save() {
								ui.label(format!("Error: {}", e));
								error!("Failed to save manifest and accounts: {}", e);
							}
							self.login_state = LoginState::HasAuth;
						},
					}
				}
				LoginState::NeedsRefresh => {
					match self.refresh_tokens_job.status() {
						JobStatus::NotStarted => {
							let transport = self.transport.clone();
							let account = account.clone();
							let ctx = ctx.clone();
							self.refresh_tokens_job.start(move || {
								let result = job_refresh_tokens(transport, account);
								ctx.request_repaint();
								result
							});
						}
						JobStatus::InProgress => {
							ui.horizontal(|ui| {
								ui.spinner();
								ui.label("Refreshing Tokens...");
							});
						}
						JobStatus::Finished => {
							debug!("refresh tokens job finished");
							let result = self.refresh_tokens_job.result();
							if let Err(e) = result {
								ui.label(format!("Error: {}", e));
								self.login_state = LoginState::NeedsLogin;
							} else {
								self.login_state = LoginState::HasAuth;
							}
						}
					};
				}
			}

			if self.login_state == LoginState::HasAuth {
				self.confirmations_widget(ctx, ui, account.clone());
			}
		});
	}
}

impl<T> Gui<T>
where
	T: Transport + Clone + Send + 'static,
{
	fn confirmations_widget(
		&mut self,
		ctx: &egui::Context,
		ui: &mut egui::Ui,
		account: Arc<RwLock<SteamGuardAccount>>,
	) {
		egui::CentralPanel::default().show_inside(ui, |ui| {
			match self.confirmations_job.status() {
				JobStatus::NotStarted => {
					if ui.button("Check Confirmations").clicked() {
						let transport = self.transport.clone();
						let account = account.clone();
						let ctx = ctx.clone();
						self.confirmations_job.start(move || {
							let result = job_fetch_confirmations(transport, account);
							ctx.request_repaint();
							result
						});
					}

					if let Some(confirmations) = self.confirmations.get(&self.selected_account) {
						match confirmations {
							Ok(confirmations) => {
								if !confirmations.is_empty() {
									for confirmation in confirmations {
										// ui.label(format!("{:?}", confirmation));
										self.render_confirmation(
											ctx,
											account.clone(),
											confirmation,
										);
									}
								} else {
									ui.label("No confirmations");
								}
							}
							Err(e) => match e {
								ConfirmerError::InvalidTokens => {
									self.login_state = LoginState::NeedsRefresh;
								}
								_ => {
									ui.label(format!("Error: {}", e));
								}
							},
						}
					}
				}
				JobStatus::InProgress => {
					ui.horizontal(|ui| {
						ui.spinner();
						ui.label("Checking...");
					});
				}
				JobStatus::Finished => {
					debug!("confirmations job finished");
					let confirmations = self.confirmations_job.result();
					self.confirmations
						.insert(self.selected_account, confirmations);
				}
			}
		});
	}

	fn render_confirmation(
		&self,
		ctx: &egui::Context,
		account: Arc<RwLock<SteamGuardAccount>>,
		confirmation: &Confirmation,
	) {
		egui::CentralPanel::default().show(ctx, |ui| {
			ui.label(&confirmation.headline);
			for line in &confirmation.summary {
				ui.label(line);
			}

			ui.horizontal(|ui| {
				let btn_accept = ui.button(&confirmation.accept);
				let btn_cancel = ui.button(&confirmation.cancel);

				let (act_on_confirmation, accept) =
					match (btn_accept.clicked(), btn_cancel.clicked()) {
						(true, false) => (true, true),
						(false, true) => (true, false),
						_ => (false, false),
					};

				if act_on_confirmation {
					let transport = self.transport.clone();
					let account = account.clone();
					let confirmation = confirmation.clone();
					let ctx = ctx.clone();
					std::thread::spawn(move || {
						let result =
							job_respond_confirmation(transport, account, confirmation, accept);
						ctx.request_repaint();
						result
					});
				}
			})
		});
	}
}

fn job_fetch_confirmations<T>(
	transport: T,
	account: Arc<RwLock<SteamGuardAccount>>,
) -> Result<Vec<Confirmation>, ConfirmerError>
where
	T: Transport + Clone,
{
	let account = account.read().unwrap();
	let confirmer = Confirmer::new(transport.clone(), &account);
	confirmer.get_trade_confirmations()
}

fn job_respond_confirmation<T>(
	transport: T,
	account: Arc<RwLock<SteamGuardAccount>>,
	confirmation: Confirmation,
	accept: bool,
) -> Result<(), ConfirmerError>
where
	T: Transport + Clone,
{
	let account = account.read().unwrap();
	let confirmer = Confirmer::new(transport.clone(), &account);
	if accept {
		confirmer.accept_confirmation(&confirmation)
	} else {
		confirmer.deny_confirmation(&confirmation)
	}
}

fn job_refresh_tokens<T>(
	transport: T,
	account: Arc<RwLock<SteamGuardAccount>>,
) -> anyhow::Result<()>
where
	T: Transport + Clone,
{
	let client = AuthenticationClient::new(transport.clone());

	let mut account = account.write().unwrap();
	let steam_id = account.steam_id;
	if let Some(tokens) = account.tokens.as_mut() {
		let mut refresher = TokenRefresher::new(client);
		let jwt = refresher.refresh(steam_id, tokens)?;
		tokens.set_access_token(jwt);
		Ok(())
	} else {
		Err(anyhow::anyhow!("No tokens"))
	}
}

#[derive(Debug)]
struct ThreadJob<T> {
	handle: Option<std::thread::JoinHandle<T>>,
}

impl<T> ThreadJob<T> {
	fn new() -> Self {
		Self {
			handle: Default::default(),
		}
	}

	pub fn start<F>(&mut self, f: F)
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		self.handle = Some(std::thread::spawn(f));
	}

	pub fn status(&self) -> JobStatus {
		let Some(handle) = self.handle.as_ref() else {
			return JobStatus::NotStarted;
		};

		if handle.is_finished() {
			JobStatus::Finished
		} else {
			JobStatus::InProgress
		}
	}

	pub fn result(&mut self) -> T {
		self.handle
			.take()
			.expect("job not started")
			.join()
			.expect("job panicked")
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobStatus {
	NotStarted,
	InProgress,
	Finished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoginState {
	Unknown,
	HasAuth,
	NeedsRefresh,
	/// Tokens are invalid or expired, and the login process has not started, or has previously failed.
	NeedsLogin,
	/// The login process has started, but requires some form of 2FA to approve the login.
	NeedsConfirmation,
	/// The login process has started, the user has submitted all necessary 2FA information, and we are waiting for the login to complete.
	WaitingForTokens,
}

fn job_begin_login<T>(
	user_login: Arc<Mutex<UserLogin<T>>>,
	account: Arc<RwLock<SteamGuardAccount>>,
	password: SecretString,
) -> Result<Vec<AllowedConfirmation>, LoginError>
where
	T: Transport + Clone,
{
	let account = account.read().unwrap();
	user_login
		.lock()
		.unwrap()
		.begin_auth_via_credentials(&account.account_name, password.expose_secret())
}

fn job_login_submit_code<T>(
	user_login: Arc<Mutex<UserLogin<T>>>,
	guard_type: EAuthSessionGuardType,
	code: String,
) -> anyhow::Result<
	CAuthentication_UpdateAuthSessionWithSteamGuardCode_Response,
	UpdateAuthSessionError,
>
where
	T: Transport + Clone,
{
	user_login
		.lock()
		.unwrap()
		.submit_steam_guard_code(guard_type, code)
}

fn job_login_poll_tokens<T>(
	user_login: Arc<Mutex<UserLogin<T>>>,
	account: Arc<RwLock<SteamGuardAccount>>,
) -> anyhow::Result<()>
where
	T: Transport + Clone,
{
	let tokens = user_login.lock().unwrap().poll_until_tokens()?;
	let mut account = account.write().unwrap();
	account.tokens = Some(tokens);

	Ok(())
}
