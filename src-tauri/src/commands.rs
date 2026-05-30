use crate::AppState;
use crate::config::DeployMode;
use crate::TokenPair;
use crate::oauth::{OAuthCallback, OAuthState};
use crate::services::ServiceStatus;
use serde::{Deserialize, Serialize};

async fn get_service_base_url(state: &tauri::State<'_, AppState>) -> String {
    state.service_manager.lock().await.get_service_url()
}

async fn ensure_server_token(state: &tauri::State<'_, AppState>) -> Result<(), String> {
    let config = state.config_manager.lock().await.get_config();
    if config.deploy_mode != DeployMode::Server {
        return Ok(());
    }
    drop(config);

    let needs_refresh = {
        let store = state.token_store.lock().await;
        match &store.tokens {
            None => true,
            Some(pair) => {
                chrono::Utc::now()
                    > pair.expires_at - chrono::Duration::minutes(5)
            }
        }
    };

    if !needs_refresh {
        return Ok(());
    }

    let refresh_token = {
        let store = state.token_store.lock().await;
        store
            .tokens
            .as_ref()
            .map(|t| t.refresh_token.clone())
            .ok_or("No refresh token available, please reconnect")?
    };

    let base_url = get_service_base_url(state).await;
    let url = format!(
        "{}/api/v1/auth/refresh",
        base_url.trim_end_matches('/')
    );
    let client = https_client_for_url(&base_url)?;

    let resp = send_and_log(
        "POST",
        &url,
        client
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .timeout(std::time::Duration::from_secs(10)),
    )
    .await
    .map_err(|e| format!("Refresh failed: {}", e))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    if body["success"].as_bool() == Some(true) {
        let mut store = state.token_store.lock().await;
        store.tokens = Some(TokenPair {
            access_token: body["access_token"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            refresh_token: body["refresh_token"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            expires_at: chrono::Utc::now()
                + chrono::Duration::seconds(
                    body["expires_in"].as_i64().unwrap_or(7200),
                ),
        });
        tracing::debug!("Server token refreshed successfully");
        Ok(())
    } else {
        let mut store = state.token_store.lock().await;
        store.tokens = None;
        Err("Session expired, please reconnect".to_string())
    }
}

async fn get_server_access_token(
    state: &tauri::State<'_, AppState>,
) -> Option<String> {
    let store = state.token_store.lock().await;
    store.tokens.as_ref().map(|t| t.access_token.clone())
}

async fn get_proxy_url(
    state: &tauri::State<'_, AppState>,
    path: &str,
) -> Result<(String, Option<String>), String> {
    let base_url = get_service_base_url(state).await;
    let config = state.config_manager.lock().await.get_config();
    let url = format!("{}/api/v1/{}", base_url.trim_end_matches('/'), path);
    let auth = match config.deploy_mode {
        DeployMode::Server => {
            ensure_server_token(state)
                .await
                .map_err(|e| format!("AUTH_EXPIRED: {}", e))?;
            get_server_access_token(state).await
        }
        DeployMode::PC => None,
    };
    Ok((url, auth))
}

async fn send_and_log(
    method: &str,
    url: &str,
    req: reqwest::RequestBuilder,
) -> Result<reqwest::Response, String> {
    tracing::info!("[HTTP] --> {} {}", method, url);
    let resp = req.send().await.map_err(|e| {
        tracing::warn!("[HTTP] <-- {} {} ERROR: {}", method, url, e);
        e.to_string()
    })?;
    let status = resp.status().as_u16();
    tracing::info!("[HTTP] <-- {} {} {}", method, url, status);
    Ok(resp)
}

fn https_client() -> Result<reqwest::Client, String> {
    let exe_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let cert_path = exe_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("clamai-cert.pem");

    let client = if cert_path.exists() {
        let cert_pem =
            std::fs::read(&cert_path).map_err(|e| format!("Read cert failed: {}", e))?;
        let cert = reqwest::Certificate::from_pem(&cert_pem)
            .map_err(|e| format!("Parse cert failed: {}", e))?;
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .build()
            .map_err(|e| format!("Build HTTPS client failed: {}", e))?
    } else {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .build()
            .map_err(|e| format!("Build HTTP client failed: {}", e))?
    };
    Ok(client)
}

pub(crate) fn https_client_for_url(remote_url: &str) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();

    if remote_url.starts_with("http://127.0.0.1")
        || remote_url.starts_with("http://localhost")
        || remote_url.starts_with("http://[::1]")
    {
        builder = builder.no_proxy();
    }

    if remote_url.starts_with("http://") {
        return builder
            .build()
            .map_err(|e| format!("Build HTTP client failed: {}", e));
    }

    let exe_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let local_cert_path = exe_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("clamai-cert.pem");

    if remote_url.starts_with("https://127.0.0.1")
        || remote_url.starts_with("https://localhost")
    {
        if local_cert_path.exists() {
            let cert_pem = std::fs::read(&local_cert_path)
                .map_err(|e| format!("Read cert failed: {}", e))?;
            let cert = reqwest::Certificate::from_pem(&cert_pem)
                .map_err(|e| format!("Parse cert failed: {}", e))?;
            return Ok(reqwest::Client::builder()
                .add_root_certificate(cert)
                .danger_accept_invalid_certs(true)
                .no_proxy()
                .build()
                .map_err(|e| format!("Build HTTPS client failed: {}", e))?);
        }
    }

    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .map_err(|e| format!("Build HTTP client failed: {}", e))
}

// ==================== OAuth命令 ====================

#[tauri::command]
pub async fn start_oauth_flow(
    state: tauri::State<'_, AppState>,
    provider_type: crate::config::OAuthProviderType,
    redirect_uri: String,
) -> Result<OAuthState, String> {
    let oauth_manager = crate::oauth::OAuthManager::new(state.config_manager.clone());
    oauth_manager
        .start_oauth_flow(provider_type, redirect_uri)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn complete_oauth_flow(
    state: tauri::State<'_, AppState>,
    callback: OAuthCallback,
) -> Result<crate::config::TokenStorage, String> {
    let oauth_manager = crate::oauth::OAuthManager::new(state.config_manager.clone());
    oauth_manager
        .complete_oauth_flow(callback)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn refresh_oauth_token(
    state: tauri::State<'_, AppState>,
    token_storage: crate::config::TokenStorage,
) -> Result<crate::config::TokenStorage, String> {
    let oauth_manager = crate::oauth::OAuthManager::new(state.config_manager.clone());
    oauth_manager
        .refresh_token(&token_storage)
        .await
        .map_err(|e| e.to_string())
}

// ==================== 代理服务命令 ====================

#[tauri::command]
pub async fn get_proxy_status(
    state: tauri::State<'_, AppState>,
) -> Result<ServiceStatus, String> {
    let service_manager = state.service_manager.lock().await;
    Ok(service_manager.get_service_status().await)
}

#[tauri::command]
pub async fn get_service_url(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let service_manager = state.service_manager.lock().await;
    Ok(service_manager.get_service_url())
}

#[tauri::command]
pub async fn get_proxy_url_cmd(
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let service_manager = state.service_manager.lock().await;
    Ok(service_manager.get_proxy_url())
}

#[tauri::command]
pub async fn get_proxy_models(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let proxy_url = {
        let service_manager = state.service_manager.lock().await;
        service_manager.get_proxy_url()
    };
    let url = format!("{}/v1/models", proxy_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()
        .map_err(|e| format!("创建HTTP客户端失败: {}", e))?;
    let resp = client.get(&url).send().await.map_err(|e| format!("请求模型列表失败: {}", e))?;
    let body = resp.text().await.map_err(|e| format!("读取响应失败: {}", e))?;
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let models = parsed
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|id| id.as_str()).map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(models)
}

#[tauri::command]
pub async fn start_proxy_service(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .start_proxy_service()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_proxy_service(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .stop_proxy_service()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn restart_proxy_service(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .restart_proxy_service()
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTestResult {
    pub success: bool,
    pub message: String,
    pub initialized: Option<bool>,
}

#[tauri::command]
pub async fn test_proxy_connectivity(
    state: tauri::State<'_, AppState>,
    proxy_url: Option<String>,
) -> Result<ProxyTestResult, String> {
    let (url, auth) = get_proxy_url(&state, "proxy/test").await?;
    let client = https_client()?;
    let mut req = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(15));
    if let Some(ref proxy) = proxy_url {
        req = req.query(&[("url", proxy)]);
    }
    if let Some(key) = &auth {
        req = req.header("Authorization", format!("Bearer {}", key));
    }
    let resp = send_and_log("GET", &url, req)
        .await
        .map_err(|e| format!("请求失败: {}", e))?;
    let result: ProxyTestResult = resp
        .json()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))?;
    Ok(result)
}

// ==================== 设置/安装向导命令 ====================

#[tauri::command]
pub async fn check_service_connection(
    service_url: String,
) -> Result<ProxyTestResult, String> {
    let url = service_url.trim_end_matches('/').to_string();
    let client = https_client()?;

    let health_url = format!("{}/health", url);
    let resp = client
        .get(&health_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("连接失败: {}", e))?;

    if !resp.status().is_success() {
        return Ok(ProxyTestResult {
            success: false,
            message: format!("服务返回状态码: {}", resp.status()),
            initialized: None,
        });
    }

    let auth_url = format!("{}/api/v1/auth/status", url);
    let auth_resp = client
        .get(&auth_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let mut initialized = None;
    if let Ok(auth_resp) = auth_resp {
        if auth_resp.status().is_success() {
            if let Ok(status) = auth_resp.json::<serde_json::Value>().await {
                initialized = status.get("initialized").and_then(|v| v.as_bool());
            }
        }
    }

    let msg = match initialized {
        Some(true) => "服务已连接，已完成初始化".to_string(),
        Some(false) => "服务已连接，尚未初始化".to_string(),
        None => "服务已连接".to_string(),
    };

    Ok(ProxyTestResult {
        success: true,
        message: msg,
        initialized,
    })
}

#[tauri::command]
pub async fn check_port_available(port: u16) -> Result<bool, String> {
    match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[tauri::command]
pub async fn complete_setup_with_config(
    state: tauri::State<'_, AppState>,
    deploy_mode: String,
    remote_url: Option<String>,
    remote_proxy_url: Option<String>,
    port: Option<u16>,
    admin_port: Option<u16>,
    use_tls: Option<bool>,
    host: Option<String>,
) -> Result<(), String> {
    let mut config_manager = state.config_manager.lock().await;
    let mut config = config_manager.get_config();

    config.deploy_mode = match deploy_mode.as_str() {
        "server" => DeployMode::Server,
        _ => DeployMode::PC,
    };
    config.remote_service_url = remote_url;
    config.remote_proxy_url = remote_proxy_url;
    if let Some(p) = port {
        config.port = p;
    }
    if let Some(ap) = admin_port {
        config.admin_port = ap;
    } else if port.is_some() {
        config.admin_port = port.unwrap() + 1;
    }
    if let Some(t) = use_tls {
        config.use_tls = t;
    }
    if let Some(ref h) = host {
        config.host = h.clone();
    }
    config.setup_complete = true;

    tracing::info!(
        "[complete_setup_with_config] Saving config: deploy_mode={}, port={:?}, host={:?}",
        deploy_mode,
        port,
        host
    );

    config_manager
        .update_config(config)
        .await
        .map_err(|e| e.to_string())?;
    drop(config_manager);

    tracing::info!(
        "[complete_setup_with_config] Config saved. Starting proxy service..."
    );

    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .start_proxy_service()
        .await
        .map_err(|e| e.to_string())?;

    tracing::info!(
        "✅ complete_setup_with_config 完成，模式: {}",
        deploy_mode
    );
    Ok(())
}

#[tauri::command]
pub async fn update_gateway_ports(
    state: tauri::State<'_, AppState>,
    port: Option<u16>,
    admin_port: Option<u16>,
) -> Result<String, String> {
    let was_running = {
        let service_manager = state.service_manager.lock().await;
        let status = service_manager.get_service_status().await;
        status.proxy_running
    };

    if was_running {
        let mut service_manager = state.service_manager.lock().await;
        tracing::info!("[update_gateway_ports] 服务运行中，先停止...");
        service_manager
            .stop_proxy_service()
            .await
            .map_err(|e| e.to_string())?;
    }

    {
        let mut config_manager = state.config_manager.lock().await;
        let mut config = config_manager.get_config();
        if let Some(p) = port {
            config.port = p;
        }
        if let Some(ap) = admin_port {
            config.admin_port = ap;
        }
        config_manager
            .update_config(config)
            .await
            .map_err(|e| e.to_string())?;
    }

    if was_running {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let mut service_manager = state.service_manager.lock().await;
        tracing::info!("[update_gateway_ports] 重启服务...");
        service_manager
            .start_proxy_service()
            .await
            .map_err(|e| e.to_string())?;
    }

    let config = state.config_manager.lock().await.get_config();
    let actual_port = config.port;
    let actual_admin = config.admin_port;
    tracing::info!(
        "✅ 网关端口已更新: proxy={}, admin={}",
        actual_port,
        actual_admin
    );

    let mut msg = format!(
        "模型端口: {}, 管理端口: {}",
        actual_port, actual_admin
    );
    if let Some(req_port) = port {
        if req_port != actual_port {
            msg = format!(
                "⚠️ 模型端口 {} 被占用，已自动调整为 {}",
                req_port, actual_port
            );
        }
    }
    if let Some(req_admin) = admin_port {
        if req_admin != actual_admin {
            msg = format!(
                "{}. 管理端口 {} 被占用，已自动调整为 {}",
                msg, req_admin, actual_admin
            );
        }
    }
    Ok(msg)
}

#[tauri::command]
pub async fn switch_deploy_mode(
    state: tauri::State<'_, AppState>,
    deploy_mode: String,
    remote_url: Option<String>,
    remote_proxy_url: Option<String>,
    port: Option<u16>,
) -> Result<(), String> {
    let mut service_manager = state.service_manager.lock().await;
    let _ = service_manager.stop_proxy_service().await;
    drop(service_manager);

    {
        let mut store = state.token_store.lock().await;
        store.tokens = None;
    }

    let mut config_manager = state.config_manager.lock().await;
    let mut config = config_manager.get_config();

    config.deploy_mode = match deploy_mode.as_str() {
        "server" => DeployMode::Server,
        _ => DeployMode::PC,
    };
    config.remote_service_url = remote_url;
    config.remote_proxy_url = remote_proxy_url;
    if let Some(p) = port {
        config.port = p;
        config.admin_port = p + 1;
    }

    config_manager
        .update_config(config)
        .await
        .map_err(|e| e.to_string())?;
    drop(config_manager);

    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .start_proxy_service()
        .await
        .map_err(|e| e.to_string())?;

    tracing::info!("✅ 已切换到 {} 模式", deploy_mode);
    Ok(())
}

#[tauri::command]
pub async fn disconnect_service(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut service_manager = state.service_manager.lock().await;
    service_manager
        .stop_proxy_service()
        .await
        .map_err(|e| e.to_string())
}

// ==================== 系统命令 ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub homepage: String,
    pub repository: String,
    pub authors: String,
    pub license: String,
}

#[tauri::command]
pub async fn get_app_info() -> AppInfo {
    AppInfo {
        name: "ClamAI".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "智能大模型网关".to_string(),
        homepage: "https://github.com/yourusername/clamai".to_string(),
        repository: "https://github.com/yourusername/clamai".to_string(),
        authors: "ClamAI Team".to_string(),
        license: "MIT".to_string(),
    }
}

#[tauri::command]
pub async fn open_log_folder() -> Result<(), String> {
    let exe_dir = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .ok_or("无法获取程序目录".to_string())?
        .to_path_buf();

    let log_dir = exe_dir.join("output");

    open::that(&log_dir).map_err(|e| e.to_string())?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub status: u16,
    pub body: String,
}

#[tauri::command]
pub async fn tauri_fetch(
    method: String,
    url: String,
    headers: Option<std::collections::HashMap<String, String>>,
    body: Option<String>,
) -> Result<FetchResponse, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| format!("创建HTTP客户端失败: {}", e))?;

    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        _ => return Err(format!("不支持的HTTP方法: {}", method)),
    };

    if let Some(h) = &headers {
        for (k, v) in h {
            req = req.header(k.as_str(), v.as_str());
        }
    }

    if let Some(b) = body {
        req = req.body(b);
    }

    tracing::info!("[tauri_fetch] --> {} {}", method, url);
    let resp = req.send().await.map_err(|e| {
        tracing::warn!("[tauri_fetch] <-- {} {} ERROR: {}", method, url, e);
        format!("HTTP请求失败 {}: {}", url, e)
    })?;
    let status = resp.status().as_u16();
    tracing::info!("[tauri_fetch] <-- {} {} {}", method, url, status);
    let resp_body = resp.text().await.map_err(|e| format!("读取响应失败: {}", e))?;

    Ok(FetchResponse {
        status,
        body: resp_body,
    })
}
