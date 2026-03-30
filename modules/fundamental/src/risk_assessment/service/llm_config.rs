use std::env;

/// LLM configuration loaded from environment variables.
///
/// Environment variables:
/// - `TRUSTD_LLM_API_URL` — LLM API endpoint URL (required)
/// - `TRUSTD_LLM_MODEL` — Model identifier (required)
/// - `TRUSTD_LLM_API_KEY` — API key for authentication (optional)
/// - `TRUSTD_LLM_TEMPERATURE` — Sampling temperature, default `0.2`
/// - `TRUSTD_LLM_TIMEOUT_SECS` — Request timeout in seconds, default `120`
/// - `TRUSTD_LLM_MAX_TOKENS` — Maximum tokens to generate (optional)
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub api_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub temperature: f32,
    pub timeout_secs: u64,
    pub max_tokens: Option<u32>,
}

impl LlmConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns `None` if `TRUSTD_LLM_API_URL` or `TRUSTD_LLM_MODEL` are not set,
    /// indicating LLM features are disabled.
    pub fn from_env() -> Option<Self> {
        let api_url = env::var("TRUSTD_LLM_API_URL").ok()?;
        let model = env::var("TRUSTD_LLM_MODEL").ok()?;

        let api_key = env::var("TRUSTD_LLM_API_KEY").ok();

        let temperature = env::var("TRUSTD_LLM_TEMPERATURE")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0.2);

        let timeout_secs = env::var("TRUSTD_LLM_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(120);

        let max_tokens = env::var("TRUSTD_LLM_MAX_TOKENS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());

        Some(Self {
            api_url,
            model,
            api_key,
            temperature,
            timeout_secs,
            max_tokens,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_returns_none_when_not_set() {
        // Without TRUSTD_LLM_API_URL and TRUSTD_LLM_MODEL set, should return None
        temp_env::with_vars_unset(["TRUSTD_LLM_API_URL", "TRUSTD_LLM_MODEL"], || {
            assert!(LlmConfig::from_env().is_none());
        });
    }

    #[test]
    fn test_from_env_with_required_vars() {
        temp_env::with_vars(
            [
                (
                    "TRUSTD_LLM_API_URL",
                    Some("http://localhost:11434/v1/chat/completions"),
                ),
                ("TRUSTD_LLM_MODEL", Some("llama3")),
            ],
            || {
                let config = LlmConfig::from_env();
                assert!(config.is_some());
                let config = config.unwrap();
                assert_eq!(config.api_url, "http://localhost:11434/v1/chat/completions");
                assert_eq!(config.model, "llama3");
                assert!(config.api_key.is_none());
                assert!((config.temperature - 0.2).abs() < f32::EPSILON);
                assert_eq!(config.timeout_secs, 120);
                assert!(config.max_tokens.is_none());
            },
        );
    }

    #[test]
    fn test_from_env_with_all_vars() {
        temp_env::with_vars(
            [
                (
                    "TRUSTD_LLM_API_URL",
                    Some("http://api.example.com/v1/chat/completions"),
                ),
                ("TRUSTD_LLM_MODEL", Some("gpt-4")),
                ("TRUSTD_LLM_API_KEY", Some("sk-test-key")),
                ("TRUSTD_LLM_TEMPERATURE", Some("0.7")),
                ("TRUSTD_LLM_TIMEOUT_SECS", Some("60")),
                ("TRUSTD_LLM_MAX_TOKENS", Some("4096")),
            ],
            || {
                let config = LlmConfig::from_env().unwrap();
                assert_eq!(config.api_url, "http://api.example.com/v1/chat/completions");
                assert_eq!(config.model, "gpt-4");
                assert_eq!(config.api_key.as_deref(), Some("sk-test-key"));
                assert!((config.temperature - 0.7).abs() < f32::EPSILON);
                assert_eq!(config.timeout_secs, 60);
                assert_eq!(config.max_tokens, Some(4096));
            },
        );
    }

    #[test]
    fn test_from_env_with_invalid_temperature_uses_default() {
        temp_env::with_vars(
            [
                (
                    "TRUSTD_LLM_API_URL",
                    Some("http://localhost:11434/v1/chat/completions"),
                ),
                ("TRUSTD_LLM_MODEL", Some("llama3")),
                ("TRUSTD_LLM_TEMPERATURE", Some("not-a-number")),
            ],
            || {
                let config = LlmConfig::from_env().unwrap();
                assert!((config.temperature - 0.2).abs() < f32::EPSILON);
            },
        );
    }
}
