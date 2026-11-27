use anyhow::{bail, Context, Result};
use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::quantized_qwen2::ModelWeights;
use pog_proto::{
    PINNED_MODEL_LICENSE_SHA256, PINNED_MODEL_TOKENIZER_SHA256, PINNED_MODEL_WEIGHTS_SHA256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokenizers::Tokenizer;

pub const MAX_PROMPT_CHARS: usize = 800;
pub const MAX_MESSAGES: usize = 12;
pub const MAX_COMPLETION_TOKENS: usize = 128;
pub const DEFAULT_COMPLETION_TOKENS: usize = 96;
const EOS_IM_END: u32 = 151645;
const EOS_ENDOFTEXT: u32 = 151643;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct GenerationOutput {
    pub text: String,
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub finish_reason: String,
}

pub trait LocalCpuModelEngine: Send + Sync {
    fn generate(
        &self,
        messages: &[ChatMessage],
        max_tokens: usize,
        temperature: f64,
        seed: u64,
    ) -> Result<GenerationOutput>;
}

/// Stream-hash a file with SHA-256 and assert exact match against a compiled-in pinned digest.
pub fn verify_file_sha256(path: &Path, expected_hex: &str, label: &str) -> Result<String> {
    let mut f =
        File::open(path).with_context(|| format!("failed to open pinned {label} at {path:?}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_hex) {
        bail!(
            "FAIL-CLOSED pinned {label} SHA-256 mismatch for {path:?}: got {actual}, expected {expected_hex}"
        );
    }
    Ok(actual)
}

/// Real CPU-only quantized Qwen2.5-0.5B-Instruct engine running strictly inside the measured TEE.
/// No GPU, no external API, no remote upstream, no fallback, and zero prompt/output logging.
pub struct CandleQwen2Engine {
    weights_path: PathBuf,
    tokenizer: Tokenizer,
    /// Guarded mutable model instance (KV cache resets cleanly per request via `ModelWeights::from_gguf`
    /// or fresh reload — wait: `quantized_qwen2::ModelWeights` keeps a KV cache that is cleanly
    /// overwritten when `index_pos == 0`!).
    model: Mutex<ModelWeights>,
}

impl CandleQwen2Engine {
    pub fn load_pinned(model_dir: &Path) -> Result<Self> {
        let weights_path = model_dir.join("qwen2.5-0.5b-instruct-q4_k_m.gguf");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let license_path = model_dir.join("LICENSE");

        verify_file_sha256(&weights_path, PINNED_MODEL_WEIGHTS_SHA256, "model weights")?;
        verify_file_sha256(
            &tokenizer_path,
            PINNED_MODEL_TOKENIZER_SHA256,
            "tokenizer.json",
        )?;
        verify_file_sha256(&license_path, PINNED_MODEL_LICENSE_SHA256, "Apache-2.0 LICENSE")?;

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("failed to load pinned tokenizer.json: {e}"))?;
        let mut f = File::open(&weights_path)?;
        let content = gguf_file::Content::read(&mut f)
            .with_context(|| format!("failed to parse GGUF header in {weights_path:?}"))?;
        let model = ModelWeights::from_gguf(content, &mut f, &Device::Cpu)
            .context("failed to load quantized Qwen2 weights onto CPU")?;

        Ok(Self {
            weights_path,
            tokenizer,
            model: Mutex::new(model),
        })
    }
}

/// Build a bounded ChatML prompt string for Qwen2.5-Instruct without ever logging its contents.
pub fn format_chatml_prompt(messages: &[ChatMessage]) -> Result<String> {
    if messages.is_empty() {
        bail!("messages must contain at least one message");
    }
    if messages.len() > MAX_MESSAGES {
        bail!("too many messages (max {MAX_MESSAGES})");
    }
    let total_chars: usize = messages.iter().map(|m| m.content.chars().count()).sum();
    if total_chars == 0 {
        bail!("prompt content cannot be empty");
    }
    if total_chars > MAX_PROMPT_CHARS {
        bail!("prompt exceeds public demo cap of {MAX_PROMPT_CHARS} characters");
    }

    let mut prompt = String::with_capacity(total_chars + 256);
    let has_system = messages
        .first()
        .map(|m| m.role.eq_ignore_ascii_case("system"))
        .unwrap_or(false);
    if !has_system {
        prompt.push_str(
            "<|im_start|>system\nYou are a helpful, concise assistant running locally on CPU inside an Intel TDX hardware enclave.<|im_end|>\n",
        );
    }
    for msg in messages {
        let role = match msg.role.to_ascii_lowercase().as_str() {
            "system" => "system",
            "assistant" => "assistant",
            _ => "user",
        };
        // Strip raw ChatML control delimiters from untrusted user input to prevent prompt spoofing.
        let sanitized = msg
            .content
            .replace("<|im_start|>", "")
            .replace("<|im_end|>", "")
            .replace("<|endoftext|>", "");
        prompt.push_str("<|im_start|>");
        prompt.push_str(role);
        prompt.push('\n');
        prompt.push_str(sanitized.trim());
        prompt.push_str("<|im_end|>\n");
    }
    prompt.push_str("<|im_start|>assistant\n");
    Ok(prompt)
}

impl LocalCpuModelEngine for CandleQwen2Engine {
    fn generate(
        &self,
        messages: &[ChatMessage],
        max_tokens: usize,
        temperature: f64,
        seed: u64,
    ) -> Result<GenerationOutput> {
        let _ = &self.weights_path;
        let prompt = format_chatml_prompt(messages)?;
        let encoding = self
            .tokenizer
            .encode(prompt, true)
            .map_err(|e| anyhow::anyhow!("tokenizer encode error: {e}"))?;
        let prompt_tokens = encoding.get_ids().to_vec();
        if prompt_tokens.is_empty() {
            bail!("empty tokenized prompt");
        }
        let max_new = max_tokens.clamp(1, MAX_COMPLETION_TOKENS);
        let temp = if temperature <= 0.05 {
            None
        } else {
            Some(temperature.clamp(0.05, 1.2))
        };
        let mut logits_processor = LogitsProcessor::new(seed, temp, Some(0.9));

        let mut model = self
            .model
            .lock()
            .map_err(|_| anyhow::anyhow!("model mutex poisoned"))?;

        let mut all_tokens = prompt_tokens.clone();
        let mut generated: Vec<u32> = Vec::with_capacity(max_new);

        // Prefill pass at pos = 0 resets KV cache cleanly for this request.
        let input = Tensor::new(prompt_tokens.as_slice(), &Device::Cpu)?.unsqueeze(0)?;
        let logits = model.forward(&input, 0)?.squeeze(0)?;
        let mut next_token = logits_processor.sample(&logits)?;
        let mut finish_reason = "length".to_string();

        for step in 0..max_new {
            if next_token == EOS_IM_END || next_token == EOS_ENDOFTEXT {
                finish_reason = "stop".to_string();
                break;
            }
            generated.push(next_token);
            all_tokens.push(next_token);
            if step + 1 >= max_new {
                break;
            }
            let pos = prompt_tokens.len() + step;
            let next_input = Tensor::new(&[next_token], &Device::Cpu)?.unsqueeze(0)?;
            let logits = model.forward(&next_input, pos)?.squeeze(0)?;
            // Light repeat penalty over recent window for clean short completions.
            let start_at = all_tokens.len().saturating_sub(48);
            let logits = candle_transformers::utils::apply_repeat_penalty(
                &logits,
                1.12,
                &all_tokens[start_at..],
            )?;
            next_token = logits_processor.sample(&logits)?;
        }

        let text = self
            .tokenizer
            .decode(&generated, true)
            .map_err(|e| anyhow::anyhow!("tokenizer decode error: {e}"))?
            .trim()
            .to_string();

        Ok(GenerationOutput {
            text,
            prompt_tokens: prompt_tokens.len(),
            completion_tokens: generated.len(),
            finish_reason,
        })
    }
}
