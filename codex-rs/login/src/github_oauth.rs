use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;

// Configuration constants for GitHub OAuth client
const SLOW_DOWN_INTERVAL_SECONDS: u64 = 5;
const MIN_POLLING_INTERVAL_SECONDS: u64 = 5;
const COPILOT_TOKEN_EXPIRY_BUFFER_SECONDS: i64 = 300; // 5 minutes

// GitHub OAuth constants for GitHub Copilot
const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98"; // GitHub Copilot CLI client ID from patch
const GITHUB_COPILOT_API_KEY_URL: &str = "https://api.github.com/copilot_internal/v2/token";
pub const GITHUB_COPILOT_AUTH_FILE: &str = "github_copilot_auth.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubTokenData {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub scope: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    // Copilot-specific fields
    pub copilot_token: Option<String>,
    pub copilot_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
struct DeviceCodeRequest {
    client_id: String,
    scope: String,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    client_id: String,
    device_code: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

// GitHub Copilot API token response
#[derive(Debug, Deserialize)]
pub struct GitHubCopilotTokenResponse {
    pub token: String,
    pub expires_at: u64, // Unix timestamp
    #[allow(dead_code)]
    pub refresh_in: u64, // Seconds until refresh
}

impl GitHubTokenData {
    /// Create a new GitHubTokenData with only the GitHub OAuth token
    pub fn new_with_github_token(
        access_token: String,
        refresh_token: Option<String>,
        token_type: String,
        scope: String,
        expires_in: Option<u64>,
    ) -> Self {
        let expires_at = expires_in
            .map(|expires_in| chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64));

        Self {
            access_token,
            refresh_token,
            token_type,
            scope,
            expires_at,
            copilot_token: None,
            copilot_expires_at: None,
        }
    }

    /// Update with Copilot token information
    pub fn with_copilot_token(mut self, copilot_token: String, expires_at: u64) -> Self {
        self.copilot_token = Some(copilot_token);
        self.copilot_expires_at = Some(
            chrono::DateTime::from_timestamp(expires_at as i64, 0).unwrap_or_else(chrono::Utc::now),
        );
        self
    }
}

pub struct GitHubOAuthClient {
    client: reqwest::Client,
}

impl GitHubOAuthClient {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .user_agent("GitHubCopilotChat/0.26.7")
            .build()?;
        Ok(Self { client })
    }

    pub async fn authenticate(
        &self,
    ) -> Result<GitHubTokenData, Box<dyn std::error::Error + Send + Sync>> {
        // Step 1: Request device code
        let device_request = DeviceCodeRequest {
            client_id: GITHUB_CLIENT_ID.to_string(),
            scope: "read:user".to_string(), // Correct scope for GitHub Copilot
        };

        let response = self
            .client
            .post(GITHUB_DEVICE_CODE_URL)
            .header("Accept", "application/json")
            .header("User-Agent", "GitHubCopilotChat/0.26.7")
            .json(&device_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GitHub device code request failed: {} - {}", status, body).into());
        }

        let device_response: DeviceCodeResponse = response.json().await?;

        // Step 2: Display user code and verification URL
        println!("GitHub Copilot Authentication");
        println!("----------------------------------------");
        println!("1. Open this URL in your browser:");
        println!("   {}", device_response.verification_uri);
        println!();
        println!("2. Enter this code when prompted:");
        println!("   {}", device_response.user_code);
        println!();

        // Try to open browser automatically with the complete URL if available
        if let Some(complete_uri) = &device_response.verification_uri_complete {
            if let Err(e) = webbrowser::open(complete_uri) {
                eprintln!("Failed to open browser automatically: {}", e);
            } else {
                println!("Browser opened automatically with the code pre-filled");
            }
        } else if let Err(e) = webbrowser::open(&device_response.verification_uri) {
            eprintln!("Failed to open browser automatically: {}", e);
        }

        println!("Waiting for authorization...");

        // Step 3: Poll for access token
        let poll_interval = Duration::from_secs(device_response.interval.max(MIN_POLLING_INTERVAL_SECONDS)); // At least MIN_POLLING_INTERVAL_SECONDS
        let expires_at =
            std::time::Instant::now() + Duration::from_secs(device_response.expires_in);

        loop {
            if std::time::Instant::now() > expires_at {
                return Err("Device code expired. Please try again.".into());
            }

            sleep(poll_interval).await;

            let token_request = DeviceTokenRequest {
                client_id: GITHUB_CLIENT_ID.to_string(),
                device_code: device_response.device_code.clone(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            };

            let response = self
                .client
                .post(GITHUB_TOKEN_URL)
                .header("Accept", "application/json")
                .header("User-Agent", "GitHubCopilotChat/0.26.7")
                .json(&token_request)
                .send()
                .await?;

            let token_response: DeviceTokenResponse = response.json().await?;

            match token_response.error.as_deref() {
                Some("authorization_pending") => {
                    // User hasn't authorized yet, continue polling
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    continue;
                }
                Some("slow_down") => {
                    // We're polling too fast, increase interval
                    sleep(Duration::from_secs(SLOW_DOWN_INTERVAL_SECONDS)).await;
                    continue;
                }
                Some("expired_token") => {
                    return Err("Device code expired. Please try again.".into());
                }
                Some("access_denied") => {
                    return Err("Access denied by user.".into());
                }
                Some(other_error) => {
                    return Err(format!(
                        "GitHub OAuth error: {} - {}",
                        other_error,
                        token_response.error_description.as_deref().unwrap_or("")
                    )
                    .into());
                }
                None => {
                    // Success! We have tokens
                    if let Some(access_token) = token_response.access_token {
                        println!(
                            "Authentication successful!"
                        );

                        // Create token data with GitHub OAuth token
                        let mut token_data = GitHubTokenData::new_with_github_token(
                            access_token,
                            token_response.refresh_token,
                            token_response
                                .token_type
                                .unwrap_or_else(|| "bearer".to_string()),
                            token_response
                                .scope
                                .unwrap_or_else(|| "read:user".to_string()),
                            token_response.expires_in,
                        );

                        // Try to get Copilot token
                        match self.get_copilot_token(&token_data.access_token).await {
                            Ok(copilot_token_response) => {
                                token_data = token_data.with_copilot_token(
                                    copilot_token_response.token,
                                    copilot_token_response.expires_at,
                                );
                                println!("Copilot token obtained successfully!");
                            }
                            Err(e) => {
                                eprintln!("Failed to get Copilot token: {}", e);
                                eprintln!(
                                    "You may need to verify your GitHub account has Copilot access."
                                );
                            }
                        }

                        return Ok(token_data);
                    } else {
                        return Err("No access token received from GitHub".into());
                    }
                }
            }
        }
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<GitHubTokenData, Box<dyn std::error::Error + Send + Sync>> {
        #[derive(Serialize)]
        struct RefreshTokenRequest {
            client_id: String,
            grant_type: String,
            refresh_token: String,
        }

        let refresh_request = RefreshTokenRequest {
            client_id: GITHUB_CLIENT_ID.to_string(),
            grant_type: "refresh_token".to_string(),
            refresh_token: refresh_token.to_string(),
        };

        let response = self
            .client
            .post(GITHUB_TOKEN_URL)
            .header("Accept", "application/json")
            .header("User-Agent", "GitHubCopilotChat/0.26.7")
            .json(&refresh_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Failed to refresh token: {} - {}", status, body).into());
        }

        let token_response: DeviceTokenResponse = response.json().await?;

        if let Some(error) = token_response.error {
            return Err(format!(
                "GitHub refresh token error: {} - {}",
                error,
                token_response.error_description.as_deref().unwrap_or("")
            )
            .into());
        }

        let access_token = token_response
            .access_token
            .ok_or("No access token in refresh response")?;
        let new_refresh_token = token_response
            .refresh_token
            .or_else(|| Some(refresh_token.to_string())); // Keep old refresh token if new one not provided

        // Create token data with refreshed GitHub OAuth token
        let mut token_data = GitHubTokenData::new_with_github_token(
            access_token,
            new_refresh_token,
            token_response
                .token_type
                .unwrap_or_else(|| "bearer".to_string()),
            token_response
                .scope
                .unwrap_or_else(|| "read:user".to_string()),
            token_response.expires_in,
        );

        // Try to get Copilot token with the new GitHub token
        match self.get_copilot_token(&token_data.access_token).await {
            Ok(copilot_token_response) => {
                token_data = token_data.with_copilot_token(
                    copilot_token_response.token,
                    copilot_token_response.expires_at,
                );
            }
            Err(e) => {
                eprintln!(
                    "Failed to get Copilot token with refreshed GitHub token: {}",
                    e
                );
            }
        }

        Ok(token_data)
    }

    /// Get Copilot token using GitHub OAuth token
    pub async fn get_copilot_token(
        &self,
        github_token: &str,
    ) -> Result<GitHubCopilotTokenResponse, Box<dyn std::error::Error + Send + Sync>> {
        let response = self
            .client
            .get(GITHUB_COPILOT_API_KEY_URL)
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {}", github_token))
            .header("User-Agent", "GitHubCopilotChat/0.26.7")
            .header("Editor-Version", "vscode/1.99.3")
            .header("Editor-Plugin-Version", "copilot-chat/0.26.7")
            .header("Openai-Version", "2024-08-22")
            .header("Openai-Beta", "chat-completions-required")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            let error_message = match status.as_u16() {
                401 => "GitHub OAuth token is invalid or expired".to_string(),
                403 => "GitHub account does not have Copilot access or insufficient permissions"
                    .to_string(),
                404 => "Copilot API endpoint not found".to_string(),
                _ => format!("Failed to get Copilot token: {} {}", status, body),
            };

            return Err(error_message.into());
        }

        let copilot_token_response: GitHubCopilotTokenResponse = response.json().await?;
        Ok(copilot_token_response)
    }
}

/// Get the path to the GitHub Copilot auth file.
fn get_github_copilot_auth_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".codex").join(GITHUB_COPILOT_AUTH_FILE)
}

/// Read the copilot token from an auth file and return it if present and not expired.
async fn get_copilot_token_from_auth_file(
    auth_path: &std::path::Path,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    if !auth_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(auth_path)?;
    let auth_data: Value = serde_json::from_str(&content)?;

    // Check if we have both copilot_token and copilot_expires_at
    if let (Some(copilot_token), Some(expires_at_str)) = (
        auth_data.get("copilot_token").and_then(|v| v.as_str()),
        auth_data.get("copilot_expires_at").and_then(|v| v.as_str()),
    ) {
        // Parse the expiration time
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str) {
            let copilot_expires_at = Some(expires_at.with_timezone(&chrono::Utc));
            
            if !is_token_expired(copilot_expires_at) {
                return Ok(Some(copilot_token.to_string()));
            }
        }
    }

    // If a GitHub access token exists, determine the appropriate refresh strategy
    if let Some(access_token) = auth_data.get("access_token").and_then(|v| v.as_str()) {
        // Check if we have expiration information
        let expires_at = if let Some(expires_at_str) = auth_data.get("expires_at").and_then(|v| v.as_str()) {
            if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                Some(expires_at.with_timezone(&chrono::Utc))
            } else {
                None
            }
        } else {
            None
        };
        
        // If expires_at is null or token is not expired, refresh copilot token
        if expires_at.is_none() || !is_token_expired(expires_at) {
            let token = refresh_copilot_token_with_access_token(access_token, auth_path).await?;
            return Ok(Some(token));
        } else if let Some(refresh_token) = auth_data.get("refresh_token").and_then(|v| v.as_str()) {
            // Token is expired, try to refresh with refresh_token
            let oauth_client = GitHubOAuthClient::new()?;
            let token_data = oauth_client.refresh_token(refresh_token).await?;
            
            // Save the updated token data
            let json_content = serde_json::to_string_pretty(&token_data)?;
            std::fs::write(auth_path, json_content)?;
            
            if let Some(copilot_token) = token_data.copilot_token {
                return Ok(Some(copilot_token));
            }
        }
    }

    Ok(None)
}

/// Get GitHub Copilot token with automatic refresh if expired, providing user-friendly error messages.
pub async fn get_github_copilot_token(
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let auth_path = get_github_copilot_auth_path();
    match get_copilot_token_from_auth_file(&auth_path).await {
        Ok(Some(token)) => Ok(token),
        Ok(None) => {
            // No auth file or no valid token, provide instructions
            Err("GitHub Copilot requires OAuth2 authentication. Run 'codex login --github-copilot' \
                 to authenticate with GitHub and obtain the necessary token.".into())
        }
        Err(e) => {
            eprintln!("Warning: Failed to refresh GitHub Copilot token: {}", e);
            // Actual error occurred during token refresh
            Err(format!("Failed to refresh GitHub Copilot token: {}. Run 'codex login --github-copilot' \
                         to re-authenticate with GitHub.", e).into())
        }
    }
}

/// Refresh the Copilot token using the given GitHub access token and persist to `auth_path`.
async fn refresh_copilot_token_with_access_token(
    access_token: &str,
    auth_path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let oauth_client = GitHubOAuthClient::new()?;

    let copilot_token_response = oauth_client.get_copilot_token(access_token).await?;

    // Read existing auth file if present
    let mut auth_data: Value = if auth_path.exists() {
        let content = std::fs::read_to_string(auth_path)?;
        serde_json::from_str(&content)?
    } else {
        Value::Object(serde_json::Map::new())
    };

    if let Some(obj) = auth_data.as_object_mut() {
        obj.insert(
            "copilot_token".to_string(),
            serde_json::Value::String(copilot_token_response.token.clone()),
        );

        if let Some(expires_at) =
            chrono::DateTime::from_timestamp(copilot_token_response.expires_at as i64, 0)
        {
            obj.insert(
                "copilot_expires_at".to_string(),
                serde_json::Value::String(expires_at.to_rfc3339()),
            );
        }
    }

    let json_content = serde_json::to_string_pretty(&auth_data)?;
    std::fs::write(auth_path, json_content)?;

    Ok(copilot_token_response.token)
}

/// Determine whether a Copilot token is expired based on its stored expiration time.
fn is_token_expired(copilot_expires_at: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    if let Some(expires_at) = copilot_expires_at {
        let now = chrono::Utc::now();
        let buffer = chrono::Duration::seconds(COPILOT_TOKEN_EXPIRY_BUFFER_SECONDS);
        // Consider token expired if it expires within the buffer period
        expires_at <= (now + buffer)
    } else {
        // If we don't have expiration info, assume expired
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_oauth_client_creation() {
        let client = GitHubOAuthClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_github_token_data_serialization() {
        let token_data = GitHubTokenData {
            access_token: "gho_test_token".to_string(),
            refresh_token: Some("ghr_refresh_token".to_string()),
            token_type: "bearer".to_string(),
            scope: "read:user".to_string(),
            expires_at: None,
            copilot_token: Some("copilot_token_123".to_string()),
            copilot_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };

        let serialized = serde_json::to_string(&token_data).unwrap();
        let deserialized: GitHubTokenData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(token_data.access_token, deserialized.access_token);
        assert_eq!(token_data.refresh_token, deserialized.refresh_token);
        assert_eq!(token_data.token_type, deserialized.token_type);
        assert_eq!(token_data.scope, deserialized.scope);
        assert_eq!(token_data.copilot_token, deserialized.copilot_token);
    }

    #[test]
    fn test_github_token_data_new_with_github_token() {
        let token_data = GitHubTokenData::new_with_github_token(
            "gho_test_token".to_string(),
            Some("ghr_refresh_token".to_string()),
            "bearer".to_string(),
            "read:user".to_string(),
            Some(3600),
        );

        assert_eq!(token_data.access_token, "gho_test_token");
        assert_eq!(
            token_data.refresh_token,
            Some("ghr_refresh_token".to_string())
        );
        assert_eq!(token_data.token_type, "bearer");
        assert_eq!(token_data.scope, "read:user");
        assert!(token_data.expires_at.is_some());
        assert_eq!(token_data.copilot_token, None);
        assert_eq!(token_data.copilot_expires_at, None);
    }

    #[test]
    fn test_github_token_data_with_copilot_token() {
        let mut token_data = GitHubTokenData::new_with_github_token(
            "gho_test_token".to_string(),
            Some("ghr_refresh_token".to_string()),
            "bearer".to_string(),
            "read:user".to_string(),
            Some(3600),
        );

        let future_timestamp = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64;
        token_data =
            token_data.with_copilot_token("copilot_token_123".to_string(), future_timestamp);

        assert_eq!(
            token_data.copilot_token,
            Some("copilot_token_123".to_string())
        );
        assert!(token_data.copilot_expires_at.is_some());
    }
}
