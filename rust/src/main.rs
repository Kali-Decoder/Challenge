use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
    native_token::sol_to_lamports,
};
use spl_token::instruction as token_instruction;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{
    Signer as DalekSigner,
    Verifier as DalekVerifier,
    Keypair as DalekKeypair,
    PublicKey as DalekPublicKey,
    Signature as DalekSignature,
};
use std::env;
use dotenv;
use reqwest::Client;
use solana_sdk::bs58;
use solana_sdk::instruction::Instruction;
use solana_sdk::program_pack::Pack;

#[derive(Serialize)]
#[serde(untagged)]
enum ApiResponse<T: Serialize> {
    Success { success: bool, data: T },
    Error { success: bool, error: String },
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Self {
        ApiResponse::Success {
            success: true,
            data,
        }
    }

    fn err(message: &str) -> Self {
        ApiResponse::Error {
            success: false,
            error: message.to_string(),
        }
    }
}

// Helper function for consistent error responses
fn error_response<T: Serialize>(message: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(ApiResponse::<T>::err(message))
}

// Helper function for success responses
fn success_response<T: Serialize>(data: T) -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse::ok(data))
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

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

#[derive(Deserialize)]
struct TokenCreateRequest {
    mint_authority: String,
    decimals: u8,
}

#[derive(Serialize)]
struct TokenCreateAccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    program_id: String,
    accounts: Vec<TokenCreateAccountMeta>,
    instruction_data: String,
    mint_pubkey: String,
    mint_secret: String,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenMintAccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenMintResponse {
    program_id: String,
    accounts: Vec<TokenMintAccountMeta>,
    instruction_data: String,
    tx_signature: String,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct MessageSignResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct MessageVerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct TokenSendRequest {
    token_mint: String,
    from_token_account: String,
    to_token_account: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenSendResponse {
    program_id: String,
    accounts: Vec<TokenCreateAccountMeta>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SolTransferRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct TransferInstructionResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct TokenTransferRequest {
    mint: String,
    from: String,
    to: String,
    owner: String,
    amount: u64,
}

async fn get_hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

async fn generate_keypair() -> impl Responder {
    use solana_sdk::signature::Keypair;
    use solana_sdk::bs58;

    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    let response = KeypairResponse { pubkey, secret };
    HttpResponse::Ok().json(ApiResponse::ok(response))
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

    let res = match client.post(solana_rpc).json(&body).send().await {
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



async fn create_token_mint(payload: web::Json<TokenCreateRequest>) -> impl Responder {
    let req = payload.into_inner();
    
    // Validate required fields
    if req.decimals > 9 {
        return error_response::<TokenCreateResponse>("Decimals must be between 0 and 9");
    }

    let result = web::block(move || {
        use solana_sdk::system_program;
        use solana_sdk::system_instruction;
        use solana_sdk::rent::Rent;
        use solana_sdk::signer::Signer;
        use solana_sdk::transaction::Transaction;
        use solana_sdk::commitment_config::CommitmentConfig;
        use solana_sdk::pubkey::Pubkey;
        use solana_client::rpc_client::RpcClient;
        use spl_token::state::Mint;
        use solana_sdk::program_pack::Pack;

        let mint_keypair = Keypair::new();
        let mint_pubkey = mint_keypair.pubkey();
        let mint_secret = bs58::encode(mint_keypair.to_bytes()).into_string();
        let mint_authority_pubkey = req.mint_authority.parse().map_err(|_| "Invalid mint authority pubkey")?;
        let decimals = req.decimals;

        // Load payer/authority from env
        let payer_secret = get_mint_authority_secret().ok_or("Missing SOLANA_MINT_AUTHORITY_SECRET in .env")?;
        let payer_bytes = bs58::decode(payer_secret).into_vec().map_err(|_| "Invalid base58 secret in .env")?;
        let payer = Keypair::from_bytes(&payer_bytes).map_err(|_| "Invalid secret key bytes in .env")?;

        let rpc_url = "https://api.devnet.solana.com";
        let client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());

        // Calculate rent-exempt minimum for mint
        let mint_rent = client.get_minimum_balance_for_rent_exemption(Mint::LEN)
            .map_err(|e| format!("Failed to get rent-exempt minimum: {e}"))?;

        // Create mint account instruction
        let create_account_ix = system_instruction::create_account(
            &payer.pubkey(),
            &mint_pubkey,
            mint_rent,
            Mint::LEN as u64,
            &spl_token::id(),
        );

        // Initialize mint instruction
        let init_mint_ix = token_instruction::initialize_mint(
            &spl_token::id(),
            &mint_pubkey,
            &mint_authority_pubkey,
            None,
            decimals,
        ).map_err(|e| format!("Failed to create instruction: {e}"))?;

        // Get recent blockhash
        let blockhash = client.get_latest_blockhash()
            .map_err(|e| format!("Failed to get blockhash: {e}"))?;

        // Build and sign transaction
        let tx = Transaction::new_signed_with_payer(
            &[create_account_ix, init_mint_ix.clone()],
            Some(&payer.pubkey()),
            &[&payer, &mint_keypair],
            blockhash,
        );

        // Send transaction
        let sig = client.send_and_confirm_transaction(&tx)
            .map_err(|e| format!("Transaction failed: {e}"))?;

        let accounts: Vec<TokenCreateAccountMeta> = init_mint_ix.accounts.iter().map(|meta| TokenCreateAccountMeta {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }).collect();
        let instruction_data = BASE64.encode(&init_mint_ix.data);
        Ok::<serde_json::Value, String>(serde_json::json!({
            "mint_pubkey": mint_pubkey.to_string(),
            "mint_secret": mint_secret,
            "tx_signature": sig.to_string(),
            "program_id": init_mint_ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }))
    }).await;

    match result {
        Ok(response) => success_response(response),
        Err(e) => error_response::<TokenCreateResponse>(&e.to_string()),
    }
}

async fn mint_tokens(payload: web::Json<TokenMintRequest>) -> impl Responder {
    let req = payload.into_inner();
    let result = web::block(move || {
        use spl_token::instruction as token_instruction;

        let mint_pubkey = req.mint.parse().map_err(|_| "Invalid mint pubkey")?;
        let dest_pubkey = req.destination.parse().map_err(|_| "Invalid destination pubkey")?;
        let amount = req.amount;

        // Load authority from env
        let authority_secret = get_mint_authority_secret().ok_or("Missing SOLANA_MINT_AUTHORITY_SECRET in .env")?;
        let authority_bytes = bs58::decode(authority_secret).into_vec().map_err(|_| "Invalid base58 secret in .env")?;
        let authority = Keypair::from_bytes(&authority_bytes).map_err(|_| "Invalid secret key bytes in .env")?;

        // Build mint_to instruction
        let ix = token_instruction::mint_to(
            &spl_token::id(),
            &mint_pubkey,
            &dest_pubkey,
            &authority.pubkey(),
            &[],
            amount,
        ).map_err(|e| format!("Failed to create instruction: {e}"))?;

        let accounts: Vec<TokenMintAccountMeta> = ix.accounts.iter().map(|meta| TokenMintAccountMeta {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }).collect();
        let instruction_data = BASE64.encode(&ix.data);
        Ok::<TokenMintResponse, String>(TokenMintResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
            tx_signature: String::new(), // Not used
        })
    }).await;

    match result {
        Ok(response) => success_response(response),
        Err(e) => error_response::<TokenMintResponse>(&e.to_string()),
    }
}

async fn send_token(payload: web::Json<TokenSendRequest>) -> impl Responder {
    let req = payload.into_inner();
    let result = web::block(move || {
        use spl_token::instruction as token_instruction;
        use solana_sdk::pubkey::Pubkey;

        let mint_pubkey = req.token_mint.parse::<Pubkey>().map_err(|_| "Invalid mint pubkey")?;
        let from_account = req.from_token_account.parse::<Pubkey>().map_err(|_| "Invalid source token account")?;
        let to_account = req.to_token_account.parse::<Pubkey>().map_err(|_| "Invalid destination token account")?;
        let owner = req.owner.parse::<Pubkey>().map_err(|_| "Invalid owner pubkey")?;
        let amount = req.amount;

        // Build transfer instruction
        let ix = token_instruction::transfer(
            &spl_token::id(),
            &from_account,
            &to_account,
            &owner,
            &[],
            amount,
        ).map_err(|e| format!("Failed to create instruction: {e}"))?;

        let accounts: Vec<TokenCreateAccountMeta> = ix.accounts.iter().map(|meta| TokenCreateAccountMeta {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        }).collect();

        let instruction_data = BASE64.encode(&ix.data);

        Ok::<TokenSendResponse, String>(TokenSendResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        })
    }).await;

    match result {
        Ok(response) => success_response(response),
        Err(e) => error_response::<TokenSendResponse>(&e.to_string()),
    }
}

async fn sign_message(payload: web::Json<MessageSignRequest>) -> impl Responder {
    let req = payload.into_inner();
    if req.message.is_empty() || req.secret.is_empty() {
        return error_response::<MessageSignResponse>("Missing required fields");
    }

    let keypair_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(b) => b,
        Err(_) => return error_response::<MessageSignResponse>("Invalid base58 secret key"),
    };

    let dalek_keypair = match DalekKeypair::from_bytes(&keypair_bytes) {
        Ok(kp) => kp,
        Err(_) => return error_response::<MessageSignResponse>("Invalid secret key bytes for Ed25519"),
    };

    let signature = dalek_keypair.sign(req.message.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes());
    let pubkey_b58 = bs58::encode(dalek_keypair.public.to_bytes()).into_string();

    success_response(MessageSignResponse {
        signature: signature_b64,
        public_key: pubkey_b58,
        message: req.message,
    })
}

async fn verify_message(payload: web::Json<MessageVerifyRequest>) -> impl Responder {
    let req = payload.into_inner();
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return error_response::<MessageVerifyResponse>("Missing required fields");
    }

    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(b) => b,
        Err(_) => return error_response::<MessageVerifyResponse>("Invalid base58 pubkey"),
    };

    let signature_bytes = match BASE64.decode(&req.signature) {
        Ok(b) => b,
        Err(_) => return error_response::<MessageVerifyResponse>("Invalid base64 signature"),
    };

    let dalek_pubkey = match DalekPublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return error_response::<MessageVerifyResponse>("Invalid public key bytes for Ed25519"),
    };

    let dalek_sig = match DalekSignature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return error_response::<MessageVerifyResponse>("Invalid signature bytes for Ed25519"),
    };

    let valid = dalek_pubkey.verify(req.message.as_bytes(), &dalek_sig).is_ok();
    success_response(MessageVerifyResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    })
}

async fn create_sol_transfer(payload: web::Json<SolTransferRequest>) -> impl Responder {
    let req = payload.into_inner();
    
    // Validate inputs
    if req.lamports == 0 {
        return error_response::<TransferInstructionResponse>("Amount must be greater than 0");
    }

    let result = web::block(move || {
        use solana_sdk::pubkey::Pubkey;
        use solana_sdk::instruction::Instruction;

        // Parse and validate addresses
        let from_pubkey = req.from.parse::<Pubkey>()
            .map_err(|_| "Invalid sender address")?;
        let to_pubkey = req.to.parse::<Pubkey>()
            .map_err(|_| "Invalid recipient address")?;

        // Create transfer instruction
        let instruction = system_instruction::transfer(
            &from_pubkey,
            &to_pubkey,
            req.lamports,
        );

        Ok::<TransferInstructionResponse, String>(TransferInstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction.accounts.iter()
                .map(|meta| meta.pubkey.to_string())
                .collect(),
            instruction_data: BASE64.encode(&instruction.data),
        })
    }).await;

    match result {
        Ok(response) => success_response(response),
        Err(e) => error_response::<TransferInstructionResponse>(&e.to_string()),
    }
}

async fn create_token_transfer(payload: web::Json<TokenTransferRequest>) -> impl Responder {
    let req = payload.into_inner();

    // Validate required fields
    if req.amount == 0 {
        return error_response::<TransferInstructionResponse>("Amount must be greater than 0");
    }

    let result = web::block(move || {
        use solana_sdk::pubkey::Pubkey;
        use spl_token::instruction as token_instruction;

        // Parse and validate addresses
        let mint_pubkey = req.mint.parse::<Pubkey>()
            .map_err(|_| "Invalid mint address")?;
        let from_account = req.from.parse::<Pubkey>()
            .map_err(|_| "Invalid source token account")?;
        let to_account = req.to.parse::<Pubkey>()
            .map_err(|_| "Invalid destination token account")?;
        let owner = req.owner.parse::<Pubkey>()
            .map_err(|_| "Invalid owner address")?;

        // Create transfer instruction
        let ix = token_instruction::transfer(
            &spl_token::id(),
            &from_account,
            &to_account,
            &owner,
            &[],
            req.amount,
        ).map_err(|e| format!("Failed to create instruction: {e}"))?;

        Ok::<TransferInstructionResponse, String>(TransferInstructionResponse {
            program_id: ix.program_id.to_string(),
            accounts: ix.accounts.iter()
                .map(|meta| meta.pubkey.to_string())
                .collect(),
            instruction_data: BASE64.encode(&ix.data),
        })
    }).await;

    match result {
        Ok(response) => success_response(response),
        Err(e) => error_response::<TransferInstructionResponse>(&e.to_string()),
    }
}

fn load_env() {
    dotenv::dotenv().ok();
}

fn get_mint_authority_pubkey() -> Option<String> {
    env::var("SOLANA_MINT_AUTHORITY_PUBKEY").ok()
}

fn get_mint_authority_secret() -> Option<String> {
    env::var("SOLANA_MINT_AUTHORITY_SECRET").ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    load_env();
    println!("🚀 Server running on http://0.0.0.0:8080");
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
            .route("/send/sol", web::post().to(create_sol_transfer))
            .route("/send/token", web::post().to(create_token_transfer))
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token_mint))
            .route("/token/mint", web::post().to(mint_tokens))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
