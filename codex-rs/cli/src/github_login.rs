use codex_login::GitHubOAuthClient;
use codex_login::GITHUB_COPILOT_AUTH_FILE;
use serde_json;
use std::fs;
use std::path::Path;

pub async fn login_github_copilot(codex_home: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Authenticating with GitHub Copilot...");

    let oauth_client = GitHubOAuthClient::new().map_err(|e| e as Box<dyn std::error::Error>)?;
    let token_data = oauth_client
        .authenticate()
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;

    // Save the token to a GitHub-specific auth file
    let github_auth_file = codex_home.join(GITHUB_COPILOT_AUTH_FILE);

    // Ensure the codex_home directory exists
    fs::create_dir_all(codex_home)?;

    // Write the token data
    let json_data = serde_json::to_string_pretty(&token_data)?;
    fs::write(&github_auth_file, json_data)?;

    // Set appropriate permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&github_auth_file)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(&github_auth_file, perms)?;
    }

    println!("Successfully authenticated with GitHub Copilot!");
    println!("Token saved to: {}", github_auth_file.display());
    println!("\nTo use GitHub Copilot with Codex, add this to your ~/.codex/config.toml:");
    println!("model_provider = \"github_copilot\"");
    println!("\nTokens will be automatically refreshed when needed.");

    Ok(())
}

