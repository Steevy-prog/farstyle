// Voice input — microphone capture (cpal) + speech-to-text. Used by the
// Workspace's recording button so the operator can dictate a prompt instead
// of typing it; the transcript is sent through the normal chat pipeline.
//
// Three backends are supported, mirroring the chat AI provider picker:
//   - OpenAI: the real Whisper transcription endpoint.
//   - Local: any OpenAI-compatible transcription server (whisper.cpp server,
//     faster-whisper-server, etc.) reachable at a user-supplied endpoint —
//     no internet round-trip, no API key required.
//   - OpenRouter: no dedicated transcription API exists there, so we route
//     the audio through an audio-capable chat model instead (input_audio
//     content block) and ask it to transcribe verbatim.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SttProvider {
    OpenAI,
    Local,
    OpenRouter,
}

impl SttProvider {
    pub fn label(&self) -> &'static str {
        match self {
            SttProvider::OpenAI     => "OpenAI Whisper",
            SttProvider::Local      => "Local (OpenAI-compatible server)",
            SttProvider::OpenRouter => "OpenRouter (audio-capable model)",
        }
    }

    pub fn all() -> &'static [SttProvider] {
        &[SttProvider::OpenAI, SttProvider::Local, SttProvider::OpenRouter]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SttProvider::OpenAI     => "openai",
            SttProvider::Local      => "local",
            SttProvider::OpenRouter => "openrouter",
        }
    }

    pub fn from_str(s: &str) -> SttProvider {
        match s {
            "local"      => SttProvider::Local,
            "openrouter" => SttProvider::OpenRouter,
            _            => SttProvider::OpenAI,
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            SttProvider::OpenAI     => "whisper-1",
            SttProvider::Local      => "whisper-1",
            SttProvider::OpenRouter => "openai/gpt-4o-audio-preview",
        }
    }
}

/// Captured audio: interleaved samples, sample rate, channel count.
pub type Capture = (Vec<f32>, u32, u16);

/// Open the default input device and record until `stop` is set, polling every
/// 50ms. Runs on a dedicated thread — the cpal `Stream` must stay alive (and is
/// not `Send` on every backend) for the duration of the capture.
pub fn record_until_stop(stop: Arc<AtomicBool>) -> Result<Capture, String> {
    let host = cpal::default_host();
    let device = host.default_input_device()
        .ok_or_else(|| "No microphone found".to_string())?;
    let config = device.default_input_config()
        .map_err(|e| format!("No usable input config: {e}"))?;
    let sample_rate = config.sample_rate().0;
    let channels = config.channels();

    let samples: Arc<Mutex<Vec<f32>>> = Arc::new(Mutex::new(Vec::new()));
    let samples_cb = samples.clone();
    let err_fn = |err| eprintln!("[voice] input stream error: {err}");

    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => device.build_input_stream(
            &config.into(),
            move |data: &[f32], _| samples_cb.lock().unwrap().extend_from_slice(data),
            err_fn, None,
        ),
        cpal::SampleFormat::I16 => device.build_input_stream(
            &config.into(),
            move |data: &[i16], _| {
                let mut buf = samples_cb.lock().unwrap();
                buf.extend(data.iter().map(|s| *s as f32 / i16::MAX as f32));
            },
            err_fn, None,
        ),
        cpal::SampleFormat::U16 => device.build_input_stream(
            &config.into(),
            move |data: &[u16], _| {
                let mut buf = samples_cb.lock().unwrap();
                buf.extend(data.iter().map(|s| (*s as f32 - 32768.0) / 32768.0));
            },
            err_fn, None,
        ),
        other => return Err(format!("Unsupported sample format: {other:?}")),
    }.map_err(|e| format!("Failed to open microphone stream: {e}"))?;

    stream.play().map_err(|e| format!("Failed to start recording: {e}"))?;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(stream);

    let data = samples.lock().unwrap().clone();
    Ok((data, sample_rate, channels))
}

/// Encode raw samples as a 16-bit PCM mono WAV (downmixing if needed) — the
/// format Whisper's API expects.
pub fn encode_wav_mono16(samples: &[f32], sample_rate: u32, channels: u16) -> Vec<u8> {
    let mono: Vec<i16> = if channels > 1 {
        samples.chunks(channels as usize)
            .map(|c| {
                let avg = c.iter().sum::<f32>() / c.len() as f32;
                (avg.clamp(-1.0, 1.0) * i16::MAX as f32) as i16
            })
            .collect()
    } else {
        samples.iter().map(|s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16).collect()
    };

    let data_len = (mono.len() * 2) as u32;
    let byte_rate = sample_rate * 2;
    let mut buf = Vec::with_capacity(44 + data_len as usize);
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&(36 + data_len).to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());  // PCM
    buf.extend_from_slice(&1u16.to_le_bytes());  // mono
    buf.extend_from_slice(&sample_rate.to_le_bytes());
    buf.extend_from_slice(&byte_rate.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());  // block align
    buf.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    buf.extend_from_slice(b"data");
    buf.extend_from_slice(&data_len.to_le_bytes());
    for s in mono {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf
}

/// Transcribe a WAV recording using the configured speech-to-text backend.
pub fn transcribe(
    provider: SttProvider,
    endpoint: &str,
    model: &str,
    api_key: &str,
    wav_bytes: Vec<u8>,
) -> Result<String, String> {
    let model = if model.trim().is_empty() { provider.default_model() } else { model };
    match provider {
        SttProvider::OpenAI => {
            if api_key.trim().is_empty() {
                return Err("No OpenAI API key configured — add one in Settings → Voice Input.".into());
            }
            let base = if endpoint.trim().is_empty() { "https://api.openai.com/v1" } else { endpoint.trim_end_matches('/') };
            transcribe_multipart(&format!("{base}/audio/transcriptions"), model, api_key, wav_bytes, "Whisper")
        }
        SttProvider::Local => {
            if endpoint.trim().is_empty() {
                return Err("No local server endpoint configured — add one in Settings → Voice Input.".into());
            }
            let base = endpoint.trim_end_matches('/');
            transcribe_multipart(&format!("{base}/audio/transcriptions"), model, api_key, wav_bytes, "Local STT")
        }
        SttProvider::OpenRouter => {
            if api_key.trim().is_empty() {
                return Err("No OpenRouter API key configured — add one in Settings → Voice Input.".into());
            }
            transcribe_via_openrouter_chat(model, api_key, wav_bytes)
        }
    }
}

/// Upload audio to an OpenAI-compatible `/audio/transcriptions` endpoint
/// (used by both the real OpenAI API and local Whisper-compatible servers).
fn transcribe_multipart(
    url: &str,
    model: &str,
    api_key: &str,
    wav_bytes: Vec<u8>,
    label: &str,
) -> Result<String, String> {
    let boundary = "----farstyle-voice-boundary";
    let mut body = Vec::with_capacity(wav_bytes.len() + 256);
    body.extend_from_slice(format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n"
    ).as_bytes());
    body.extend_from_slice(format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"recording.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
    ).as_bytes());
    body.extend_from_slice(&wav_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut req = ureq::post(url)
        .set("Content-Type", &format!("multipart/form-data; boundary={boundary}"));
    if !api_key.trim().is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", api_key));
    }
    let resp = req.send_bytes(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, response) => {
                let body = response.into_string().unwrap_or_default();
                let detail = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.pointer("/error/message").map(|m| m.to_string()))
                    .unwrap_or(body);
                format!("{label} API error {}: {}", code, detail)
            }
            other => format!("{label} request failed: {}", other),
        })?;

    let parsed: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
    parsed.get("text")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{label} response had no text field"))
}

/// Transcribe by sending the audio as an `input_audio` content block to an
/// audio-capable chat model via OpenRouter — there is no separate
/// transcription endpoint on OpenRouter, so this rides the chat completions
/// API instead.
fn transcribe_via_openrouter_chat(model: &str, api_key: &str, wav_bytes: Vec<u8>) -> Result<String, String> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wav_bytes);
    let body = serde_json::json!({
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                { "type": "text", "text": "Transcribe this audio recording verbatim. Reply with only the transcribed text, no commentary." },
                { "type": "input_audio", "input_audio": { "data": b64, "format": "wav" } }
            ]
        }]
    });

    let resp = ureq::post("https://openrouter.ai/api/v1/chat/completions")
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", api_key))
        .set("HTTP-Referer", "https://farstyle.app")
        .set("X-Title", "FarStyle Security Auditor")
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, response) => {
                let body = response.into_string().unwrap_or_default();
                let detail = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.pointer("/error/message").or_else(|| v.pointer("/error")).map(|m| m.to_string()))
                    .unwrap_or(body);
                format!("OpenRouter API error {}: {}", code, detail)
            }
            other => format!("OpenRouter request failed: {}", other),
        })?;

    let parsed: serde_json::Value = resp.into_json().map_err(|e| e.to_string())?;
    parsed.pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "OpenRouter response had no transcript content".to_string())
}
