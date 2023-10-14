use std::collections::HashMap;

use log::*;

use steamguard::{
	refresher::TokenRefresher, steamapi::AuthenticationClient, Confirmation, Confirmer,
	ConfirmerError,
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

struct Gui<T> {
	transport: T,
	manager: AccountManager,
	_args: GuiCommand,
	_globalargs: GlobalArgs,

	selected_account: usize,
	confirmations: Arc<Mutex<HashMap<usize, Result<Vec<Confirmation>, ConfirmerError>>>>,

	confirmations_job: Option<std::thread::JoinHandle<Result<Vec<Confirmation>, ConfirmerError>>>,
	refresh_tokens_job: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
}

impl<T> Gui<T> {
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

			confirmations_job: None,
			refresh_tokens_job: None,
		}
	}
}

impl<T> eframe::App for Gui<T>
where
	T: Transport + Clone + Send + 'static,
{
	fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
		egui::CentralPanel::default().show(ctx, |ui| {
			let selected_account_name = self
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
						ui.selectable_value(
							&mut self.selected_account,
							i,
							entry.account_name.clone(),
						);
					}
				});

			let account = self
				.manager
				.get_or_load_account(&selected_account_name)
				.unwrap();
			let mut code = account.read().unwrap().generate_code(
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			);

			egui::TextEdit::singleline(&mut code)
				.interactive(false)
				.show(ui);

			ui.add(egui::Separator::default());

			if ui.button("Check Confirmations").clicked() {
				let transport = self.transport.clone();
				let account = account.clone();
				let ctx = ctx.clone();
				self.confirmations_job = Some(std::thread::spawn(move || {
					let result = job_fetch_confirmations(transport, account);
					ctx.request_repaint();
					result
				}));
			}

			if self
				.confirmations_job
				.as_ref()
				.is_some_and(|j| j.is_finished())
			{
				debug!("confirmations job finished");
				let job = self.confirmations_job.take().unwrap();
				let confirmations = job.join().unwrap();
				self.confirmations
					.lock()
					.unwrap()
					.insert(self.selected_account, confirmations);
			} else if self.confirmations_job.is_some() {
				ui.spinner();
			} else {
				let confirmations = self.confirmations.lock().unwrap();
				if let Some(confirmations) = confirmations.get(&self.selected_account) {
					match confirmations {
						Ok(confirmations) => {
							if !confirmations.is_empty() {
								for confirmation in confirmations {
									// ui.label(format!("{:?}", confirmation));
									self.render_confirmation(ctx, account.clone(), confirmation);
								}
							} else {
								ui.label("No confirmations");
							}
						}
						Err(e) => {
							ui.label(format!("Error: {}", e));
						}
					}
				}
			}
		});
	}
}

impl<T> Gui<T>
where
	T: Transport + Clone + Send + 'static,
{
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
		let jwt = refresher.refresh(steam_id, &tokens)?;
		tokens.set_access_token(jwt);
		Ok(())
	} else {
		Err(anyhow::anyhow!("No tokens"))
	}
}
