use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use uuid::Uuid; 
use std::sync::Mutex;
use chrono::{DateTime, Utc};
use reqwest::Client;
use solana_sdk::bs58;
use solana_sdk::{
    signature::{Keypair, Signer},
    pubkey::Pubkey,
    system_instruction,
    transaction::Transaction,
    native_token::sol_to_lamports,
};
use solana_client::rpc_client::RpcClient;

#[derive(Deserialize)]
struct BalanceRequest {
    address: String,
}

#[derive(Deserialize)]
pub struct TransferRequest {
    from_secret_key: String, 
    to_address: String,
    amount_sol: f64,
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    lamports: u64,
    sol: f64,
}





async fn get_hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

async fn get_balance_json(payload: web::Json<BalanceRequest>) -> impl Responder {
    let client = Client::new();
    let solana_rpc = "https://api.devnet.solana.com";

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [payload.address]
    });

    let res = match client.post(solana_rpc)
        .json(&body)
        .send()
        .await {
            Ok(r) => r,
            Err(_) => return HttpResponse::InternalServerError().body("Failed to call Solana RPC"),
        };

    let json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(_) => return HttpResponse::InternalServerError().body("Invalid JSON response"),
    };

    let lamports = json["result"]["value"].as_u64().unwrap_or(0);
    let sol = lamports as f64 / 1_000_000_000.0;

    HttpResponse::Ok().json(BalanceResponse {
        address: payload.address.clone(),
        lamports,
        sol,
    })
}

pub async fn transfer_sol(payload: web::Json<TransferRequest>) -> impl Responder {
    let rpc_url = "https://api.devnet.solana.com".to_string();
    let payload = payload.into_inner();
    println!("Transfer request:");
    if payload.from_secret_key.is_empty() || payload.to_address.is_empty() || payload.amount_sol <= 0.0 {
        return HttpResponse::BadRequest().body("Invalid transfer request parameters");
    }
    let result = web::block(move || {
        let client = RpcClient::new(rpc_url);

        let keypair_bytes = bs58::decode(&payload.from_secret_key).into_vec()
            .map_err(|_| "Invalid base58 secret key")?;
        let from_keypair = Keypair::from_bytes(&keypair_bytes)
            .map_err(|_| "Invalid secret key bytes")?;
        let to_pubkey: Pubkey = payload.to_address.parse()
            .map_err(|_| "Invalid destination address")?;
        let lamports = sol_to_lamports(payload.amount_sol);

        let blockhash = client.get_latest_blockhash()
            .map_err(|_| "Failed to get recent blockhash")?;

        let instruction = system_instruction::transfer(
            &from_keypair.pubkey(),
            &to_pubkey,
            lamports,
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&from_keypair.pubkey()),
            &[&from_keypair],
            blockhash,
        );

        let sig = client.send_and_confirm_transaction(&tx)
            .map_err(|e| format!("Transaction failed: {}", e))?;

        Ok::<_, String>(sig)
    }).await;

    match result {
        Ok(sig) => HttpResponse::Ok().body(format!("✅ Transfer successful. Signature: {:?}", sig)),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("❌ Transfer failed: {:?}", e))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  
    println!("🚀 Server running on http://127.0.0.1:8080");
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            // .app_data(app_state.clone())
            .wrap(cors)
            .route("/", web::get().to(get_hello_world))
            .route("/balance", web::post().to(get_balance_json))
            .route("/transfer", web::post().to(transfer_sol))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
