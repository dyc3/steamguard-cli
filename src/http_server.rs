use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use log::*;
use crate::commands::confirm::{ConfirmCommand, DeclineCommand};
use steamguard::{SteamGuardAccount, transport::Transport};

#[derive(Debug, Deserialize)]
pub struct ConfirmRequest {
    pub action: String,
    pub trade_offer_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeclineRequest {
    pub action: String,
    pub trade_offer_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ConfirmationInfo {
    pub id: String,
    pub creator_id: String,
    pub headline: String,
    pub summary: String,
    pub conf_type: String,
}

pub struct HttpServer<T: Transport + Clone + Send + Sync + 'static> {
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
}

impl<T: Transport + Clone + Send + Sync + 'static> HttpServer<T> {
    pub fn new(
        transport: T,
        accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
    ) -> Self {
        Self {
            transport,
            accounts,
        }
    }

    pub async fn start(&self, port: u16) -> Result<(), anyhow::Error> {
        use warp::Filter;

        let transport = self.transport.clone();
        let accounts = self.accounts.clone();

        // CORS headers for browser extension
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(vec!["GET", "POST", "OPTIONS"]);

        // Health check endpoint
        let health = warp::path("health")
            .and(warp::get())
            .map(|| {
                warp::reply::json(&ApiResponse {
                    success: true,
                    message: "Server is running".to_string(),
                    data: None,
                })
            });

        // List confirmations endpoint
        let transport_clone = transport.clone();
        let accounts_clone = accounts.clone();
        let list_confirmations = warp::path("confirmations")
            .and(warp::get())
            .and_then(move || {
                let transport = transport_clone.clone();
                let accounts = accounts_clone.clone();
                async move {
                    handle_list_confirmations(transport, accounts).await
                }
            });

        // Confirm trade endpoint
        let transport_clone = transport.clone();
        let accounts_clone = accounts.clone();
        let confirm_trade = warp::path("confirm")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |request: ConfirmRequest| {
                let transport = transport_clone.clone();
                let accounts = accounts_clone.clone();
                async move {
                    handle_confirm_request(request, transport, accounts).await
                }
            });

        // Decline trade endpoint
        let transport_clone = transport.clone();
        let accounts_clone = accounts.clone();
        let decline_trade = warp::path("decline")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |request: DeclineRequest| {
                let transport = transport_clone.clone();
                let accounts = accounts_clone.clone();
                async move {
                    handle_decline_request(request, transport, accounts).await
                }
            });

        let routes = health
            .or(list_confirmations)
            .or(confirm_trade)
            .or(decline_trade)
            .with(cors);

        info!("HTTP API server starting on port {}", port);
        info!("Available endpoints:");
        info!("  GET  http://localhost:{}/health", port);
        info!("  GET  http://localhost:{}/confirmations", port);
        info!("  POST http://localhost:{}/confirm", port);
        info!("  POST http://localhost:{}/decline", port);

        warp::serve(routes)
            .run(([127, 0, 0, 1], port))
            .await;

        Ok(())
    }
}

async fn handle_list_confirmations<T: Transport + Clone + Send + Sync + 'static>(
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match list_confirmations(transport, &accounts).await {
        Ok(confirmations) => {
            Ok(warp::reply::json(&ApiResponse {
                success: true,
                message: format!("Found {} confirmations", confirmations.len()),
                data: Some(serde_json::to_value(confirmations).unwrap()),
            }))
        }
        Err(e) => {
            error!("Failed to list confirmations: {}", e);
            Ok(warp::reply::json(&ApiResponse {
                success: false,
                message: format!("Failed to list confirmations: {}", e),
                data: None,
            }))
        }
    }
}

async fn handle_confirm_request<T: Transport + Clone + Send + Sync + 'static>(
    request: ConfirmRequest,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let cmd = match request.action.as_str() {
        "latest" => ConfirmCommand {
            accept_all: false,
            fail_fast: false,
            latest: true,
            trade_offer_id: None,
        },
        "trade" => {
            if let Some(trade_id) = request.trade_offer_id {
                ConfirmCommand {
                    accept_all: false,
                    fail_fast: false,
                    latest: false,
                    trade_offer_id: Some(trade_id),
                }
            } else {
                return Ok(warp::reply::json(&ApiResponse {
                    success: false,
                    message: "trade_offer_id is required for 'trade' action".to_string(),
                    data: None,
                }));
            }
        }
        "all" => ConfirmCommand {
            accept_all: true,
            fail_fast: false,
            latest: false,
            trade_offer_id: None,
        },
        _ => {
            return Ok(warp::reply::json(&ApiResponse {
                success: false,
                message: "Invalid action. Use 'latest', 'trade', or 'all'".to_string(),
                data: None,
            }));
        }
    };

    match execute_confirm_command(cmd, transport, accounts).await {
        Ok(_) => {
            Ok(warp::reply::json(&ApiResponse {
                success: true,
                message: format!("Successfully executed {} action", request.action),
                data: None,
            }))
        }
        Err(e) => {
            error!("Failed to execute confirm command: {}", e);
            Ok(warp::reply::json(&ApiResponse {
                success: false,
                message: format!("Failed to execute command: {}", e),
                data: None,
            }))
        }
    }
}

async fn handle_decline_request<T: Transport + Clone + Send + Sync + 'static>(
    request: DeclineRequest,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let cmd = match request.action.as_str() {
        "latest" => DeclineCommand {
            decline_all: false,
            fail_fast: false,
            latest: true,
            trade_offer_id: None,
        },
        "trade" => {
            if let Some(trade_id) = request.trade_offer_id {
                DeclineCommand {
                    decline_all: false,
                    fail_fast: false,
                    latest: false,
                    trade_offer_id: Some(trade_id),
                }
            } else {
                return Ok(warp::reply::json(&ApiResponse {
                    success: false,
                    message: "trade_offer_id is required for 'trade' action".to_string(),
                    data: None,
                }));
            }
        }
        "all" => DeclineCommand {
            decline_all: true,
            fail_fast: false,
            latest: false,
            trade_offer_id: None,
        },
        _ => {
            return Ok(warp::reply::json(&ApiResponse {
                success: false,
                message: "Invalid action. Use 'latest', 'trade', or 'all'".to_string(),
                data: None,
            }));
        }
    };

    match execute_decline_command(cmd, transport, accounts).await {
        Ok(_) => {
            Ok(warp::reply::json(&ApiResponse {
                success: true,
                message: format!("Successfully executed {} action", request.action),
                data: None,
            }))
        }
        Err(e) => {
            error!("Failed to execute decline command: {}", e);
            Ok(warp::reply::json(&ApiResponse {
                success: false,
                message: format!("Failed to execute command: {}", e),
                data: None,
            }))
        }
    }
}

async fn execute_confirm_command<T: Transport + Clone + Send + Sync + 'static>(
    cmd: ConfirmCommand,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<(), anyhow::Error> {
    // Execute the confirmation logic directly without going through the full command structure
    tokio::task::spawn_blocking(move || {
        execute_confirmation_logic(cmd, transport, accounts)
    }).await?
}

fn execute_confirmation_logic<T: Transport + Clone + Send + Sync + 'static>(
    cmd: ConfirmCommand,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<(), anyhow::Error> {
    use steamguard::{Confirmer, ConfirmerError};
    
    for account_arc in accounts {
        let account = account_arc.lock().unwrap();
        
        info!("{}: Checking for confirmations", account.account_name);
        let confirmations = loop {
            let confirmer = Confirmer::new(transport.clone(), &*account);
            match confirmer.get_confirmations() {
                Ok(confs) => break confs,
                Err(ConfirmerError::InvalidTokens) => {
                    info!("obtaining new tokens");
                    // For simplicity, we'll just return an error here
                    // In a full implementation, you'd want to handle re-login
                    return Err(anyhow::anyhow!("Invalid tokens - re-login required"));
                }
                Err(err) => {
                    error!("Failed to get confirmations: {}", err);
                    return Err(err.into());
                }
            }
        };

        if confirmations.is_empty() {
            info!("{}: No confirmations", account.account_name);
            continue;
        }

        let confirmer = Confirmer::new(transport.clone(), &*account);
        
        if cmd.accept_all {
            info!("accepting all confirmations");
            confirmer.accept_confirmations_bulk(&confirmations)?;
        } else if cmd.latest {
            info!("accepting latest confirmation");
            if let Some(latest_conf) = confirmations.first() {
                confirmer.accept_confirmations_bulk(&vec![latest_conf.clone()])?;
                info!("Successfully accepted latest confirmation: {}", latest_conf.description());
            }
        } else if let Some(ref trade_id) = cmd.trade_offer_id {
            info!("looking for confirmation with trade offer ID: {}", trade_id);
            let matching_conf = confirmations.iter().find(|conf| {
                conf.creator_id == *trade_id
            });
            
            if let Some(conf) = matching_conf {
                info!("found matching confirmation: {}", conf.description());
                confirmer.accept_confirmations_bulk(&vec![conf.clone()])?;
                info!("Successfully accepted confirmation for trade offer ID: {}", trade_id);
            } else {
                warn!("No confirmation found for trade offer ID: {}", trade_id);
                for conf in &confirmations {
                    info!("Available confirmation - ID: {}, Creator ID: {}, Description: {}", 
                        conf.id, conf.creator_id, conf.description());
                }
            }
        }
    }
    
    Ok(())
}

async fn execute_decline_command<T: Transport + Clone + Send + Sync + 'static>(
    cmd: DeclineCommand,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<(), anyhow::Error> {
    // Execute the decline logic directly without going through the full command structure
    tokio::task::spawn_blocking(move || {
        execute_decline_logic(cmd, transport, accounts)
    }).await?
}

fn execute_decline_logic<T: Transport + Clone + Send + Sync + 'static>(
    cmd: DeclineCommand,
    transport: T,
    accounts: Vec<Arc<Mutex<SteamGuardAccount>>>,
) -> Result<(), anyhow::Error> {
    use steamguard::{Confirmer, ConfirmerError};
    
    for account_arc in accounts {
        let account = account_arc.lock().unwrap();
        
        info!("{}: Checking for confirmations", account.account_name);
        let confirmations = loop {
            let confirmer = Confirmer::new(transport.clone(), &*account);
            match confirmer.get_confirmations() {
                Ok(confs) => break confs,
                Err(ConfirmerError::InvalidTokens) => {
                    info!("obtaining new tokens");
                    // For simplicity, we'll just return an error here
                    // In a full implementation, you'd want to handle re-login
                    return Err(anyhow::anyhow!("Invalid tokens - re-login required"));
                }
                Err(err) => {
                    error!("Failed to get confirmations: {}", err);
                    return Err(err.into());
                }
            }
        };

        if confirmations.is_empty() {
            info!("{}: No confirmations", account.account_name);
            continue;
        }

        let confirmer = Confirmer::new(transport.clone(), &*account);
        
        fn submit_loop(
            submit: impl Fn() -> Result<(), ConfirmerError>,
            fail_fast: bool,
        ) -> Result<(), ConfirmerError> {
            let mut attempts = 0;
            loop {
                match submit() {
                    Ok(_) => break,
                    Err(ConfirmerError::InvalidTokens) => {
                        error!("Invalid tokens, but they should be valid already. This is weird, stopping.");
                        return Err(ConfirmerError::InvalidTokens);
                    }
                    Err(ConfirmerError::NetworkFailure(err)) => {
                        error!("{}", err);
                        return Err(ConfirmerError::NetworkFailure(err));
                    }
                    Err(ConfirmerError::DeserializeError(err)) => {
                        error!("Failed to deserialize the response, but the submission may have succeeded: {}", err);
                        return Err(ConfirmerError::DeserializeError(err));
                    }
                    Err(err) => {
                        warn!("submit decline result: {}", err);
                        if fail_fast || attempts >= 3 {
                            return Err(err);
                        }

                        attempts += 1;
                        let wait = std::time::Duration::from_secs(3 * attempts);
                        info!(
                            "retrying in {} seconds (attempt {})",
                            wait.as_secs(),
                            attempts
                        );
                        std::thread::sleep(wait);
                    }
                }
            }
            Ok(())
        }
        
        if cmd.decline_all {
            info!("declining all confirmations");
            submit_loop(
                || confirmer.deny_confirmations_bulk(&confirmations),
                cmd.fail_fast,
            )?;
        } else if cmd.latest {
            info!("declining latest confirmation");
            if let Some(latest_conf) = confirmations.first() {
                submit_loop(
                    || confirmer.deny_confirmations_bulk(&vec![latest_conf.clone()]),
                    cmd.fail_fast,
                )?;
                info!("Successfully declined latest confirmation: {}", latest_conf.description());
            }
        } else if let Some(ref trade_id) = cmd.trade_offer_id {
            info!("looking for confirmation with trade offer ID: {}", trade_id);
            let matching_conf = confirmations.iter().find(|conf| {
                conf.creator_id == *trade_id
            });
            
            if let Some(conf) = matching_conf {
                info!("found matching confirmation: {}", conf.description());
                submit_loop(
                    || confirmer.deny_confirmations_bulk(&vec![conf.clone()]),
                    cmd.fail_fast,
                )?;
                info!("Successfully declined confirmation for trade offer ID: {}", trade_id);
            } else {
                warn!("No confirmation found for trade offer ID: {}", trade_id);
                for conf in &confirmations {
                    info!("Available confirmation - ID: {}, Creator ID: {}, Description: {}", 
                        conf.id, conf.creator_id, conf.description());
                }
            }
        }
    }
    
    Ok(())
}

async fn list_confirmations<T: Transport + Clone + Send + Sync + 'static>(
    transport: T,
    accounts: &[Arc<Mutex<SteamGuardAccount>>],
) -> Result<Vec<ConfirmationInfo>, anyhow::Error> {
    let mut all_confirmations = Vec::new();
    
    for account_arc in accounts {
        let account = account_arc.lock().unwrap();
        let confirmer = steamguard::Confirmer::new(transport.clone(), &*account);
        
        match confirmer.get_confirmations() {
            Ok(confirmations) => {
                for conf in confirmations {
                    all_confirmations.push(ConfirmationInfo {
                        id: conf.id,
                        creator_id: conf.creator_id,
                        headline: conf.headline,
                        summary: conf.summary.join(", "),
                        conf_type: format!("{:?}", conf.conf_type),
                    });
                }
            }
            Err(e) => {
                warn!("Failed to get confirmations for account {}: {}", account.account_name, e);
            }
        }
    }
    
    Ok(all_confirmations)
}