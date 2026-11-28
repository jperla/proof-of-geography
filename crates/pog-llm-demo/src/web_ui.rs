//! Verified LLM Demo Website — embedded directly inside the measured `FROM scratch` enclave binary!
//!
//! Because this HTML/CSS/JS is compiled into the measured binary itself, the GCP Confidential Space
//! Intel TDX container digest measures BOTH the demo UI AND the inference/TLS/prover/signer runtime.

pub const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Verified LLM — Proof of Geography (CPU Intel TDX Enclave)</title>
  <meta name="description" content="End-to-end hardware-attested CPU-only LLM demo inside Intel TDX Confidential Space with OpenAI-compatible API, end-to-end TLS 1.3 EKM binding, and independent CLI/SDK verification." />
  <style>
    :root {
      --bg: #060b16; --panel: #0d1526; --panel-2: #111c33; --border: #1e2d4d;
      --text: #e6edf8; --muted: #94a3b8; --cyan: #38bdf8; --emerald: #34d399;
      --amber: #fbbf24; --rose: #fb7185; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: var(--sans); background: var(--bg); color: var(--text); line-height: 1.5; }
    a { color: var(--cyan); text-decoration: none; }
    a:hover { text-decoration: underline; }
    header {
      position: sticky; top: 0; z-index: 20; background: rgba(6,11,22,0.92);
      backdrop-filter: blur(10px); border-bottom: 1px solid var(--border);
      padding: 12px 20px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--emerald); box-shadow: 0 0 10px var(--emerald); }
    .nav { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .pill {
      padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border);
      background: var(--panel); color: var(--text); font-size: 13px; font-weight: 600;
    }
    .pill.active { border-color: var(--cyan); color: var(--cyan); background: rgba(56,189,248,0.1); }
    .container { max-width: 1120px; margin: 0 auto; padding: 24px 18px 64px; }
    .banner {
      border-radius: 12px; padding: 14px 16px; margin-bottom: 18px; border: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(56,189,248,0.08), rgba(52,211,153,0.05));
    }
    .banner.warn {
      border-color: rgba(251,191,36,0.45);
      background: rgba(251,191,36,0.08);
    }
    .banner strong { display: block; margin-bottom: 4px; font-size: 14px; }
    .banner p { margin: 0; color: var(--muted); font-size: 13px; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 18px; }
    .card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 18px;
    }
    h1 { margin: 0 0 8px; font-size: 26px; letter-spacing: -0.02em; }
    h2 { margin: 0 0 10px; font-size: 16px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .badge {
      font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;
      padding: 3px 8px; border-radius: 6px; font-family: var(--mono);
    }
    .badge.ok { background: rgba(52,211,153,0.15); color: var(--emerald); border: 1px solid rgba(52,211,153,0.4); }
    .badge.warn { background: rgba(251,191,36,0.15); color: var(--amber); border: 1px solid rgba(251,191,36,0.4); }
    .badge.info { background: rgba(56,189,248,0.15); color: var(--cyan); border: 1px solid rgba(56,189,248,0.4); }
    .kv { display: grid; grid-template-columns: 155px 1fr; gap: 6px 10px; font-size: 12.5px; margin-top: 8px; }
    .kv .k { color: var(--muted); }
    .kv .v { font-family: var(--mono); word-break: break-all; color: var(--text); }
    textarea {
      width: 100%; min-height: 92px; border-radius: 10px; border: 1px solid var(--border);
      background: #080f1f; color: var(--text); padding: 12px; font-family: var(--sans); font-size: 14px; resize: vertical;
    }
    .controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-top: 10px; }
    button {
      cursor: pointer; border-radius: 10px; border: 1px solid var(--border); padding: 10px 16px;
      font-weight: 600; font-size: 14px; background: var(--panel-2); color: var(--text);
    }
    button.primary { background: linear-gradient(135deg, #0284c7, #059669); border: none; color: #fff; }
    button.primary:disabled { opacity: 0.55; cursor: wait; }
    button.chip { padding: 5px 10px; font-size: 12px; font-weight: 500; border-radius: 8px; }
    .output-box {
      margin-top: 14px; background: #080f1f; border: 1px solid var(--border); border-radius: 10px;
      padding: 14px; min-height: 76px; white-space: pre-wrap; font-size: 14.5px;
    }
    .muted { color: var(--muted); font-size: 13px; }
    .mono { font-family: var(--mono); }
    pre {
      background: #080f1f; border: 1px solid var(--border); border-radius: 10px; padding: 12px;
      overflow-x: auto; font-size: 12px; font-family: var(--mono); color: #cbd5e1; margin: 8px 0 0;
    }
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 8px; }
    th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    .tabs { display: flex; gap: 6px; margin-bottom: 10px; flex-wrap: wrap; }
    .tab-btn.active { border-color: var(--cyan); color: var(--cyan); }
    .hidden { display: none; }
    svg { width: 100%; height: auto; display: block; margin-top: 8px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="dot"></div>
      <span>Proof of Geography · Verified LLM Demo</span>
    </div>
    <nav class="nav">
      <a class="pill" href="https://proofofgeography.com/">← Locate Me (Visitor)</a>
      <a class="pill active" href="/">🤖 Verified LLM (Server)</a>
      <a class="pill" href="/v1/info" target="_blank" rel="noopener">Live /v1/info JSON</a>
      <a class="pill" href="https://github.com/jperla/proof-of-geography" target="_blank" rel="noopener">GitHub ↗</a>
    </nav>
  </header>

  <main class="container">
    <div class="banner">
      <strong>Two Distinct Demos: This page locates &amp; attests the SERVER generating the completion — NOT your browser.</strong>
      <p>
        For visitor geolocation estimates, use <a href="https://proofofgeography.com/">Locate Me</a>.
        This Verified LLM page, its OpenAI-compatible <code>/v1/chat/completions</code> API, its end-to-end TLS 1.3 socket, its local CPU-only model (<code>Qwen2.5-0.5B-Instruct</code> Q4_K_M, Apache-2.0), and its nonexportable Ed25519 receipt signer all run inside the <strong>exact same measured Intel TDX Confidential Space image</strong> with zero GPU, zero external inference API, zero SSH, and zero prompt/output logging.
      </p>
    </div>

    <div class="banner warn">
      <strong>⚠️ Browser View ≠ Independent End-to-End TLS Verification</strong>
      <p>
        Ordinary browser JavaScript cannot read RFC 8446 §7.5 TLS 1.3 Exported Keying Material (<code>EXPORTER-pog-inference-v1</code>) or independently verify the HTML/JS it just downloaded without trusting this page.
        Use this browser playground to test real prompts and download receipts, then run the <strong>one-command independent CLI client</strong> or <strong>OpenAI SDK verifying transport</strong> below to establish and verify your own real TLS 1.3 session + Google Intel TDX hardware chain without trusting this website.
      </p>
    </div>

    <!-- Separate Statuses: Inference Hardware TEE vs Geographic Proof Quorum -->
    <div class="grid-2">
      <section class="card">
        <h2>
          <span>1. Inference Workload TEE Attestation</span>
          <span id="badge-tee" class="badge info">Loading…</span>
        </h2>
        <div class="kv" id="kv-tee">
          <div class="k">Hardware TEE</div><div class="v">Loading…</div>
        </div>
      </section>

      <section class="card">
        <h2>
          <span>2. Server Geographic Proof (Separate)</span>
          <span id="badge-geo" class="badge warn">Loading…</span>
        </h2>
        <div class="kv" id="kv-geo">
          <div class="k">Production Quorum</div><div class="v">Loading…</div>
        </div>
        <details style="margin-top:10px;">
          <summary class="muted" style="cursor:pointer;">Diagnostic-only anchor RTT observations (NOT hardware proof)</summary>
          <div id="diag-table-wrap" class="muted" style="margin-top:6px;">Loading…</div>
        </details>
      </section>
    </div>

    <!-- Real CPU LLM Playground -->
    <section class="card" style="margin-bottom:18px;">
      <h2>
        <span>Prompt the Measured CPU Enclave (<code>POST /v1/chat/completions</code>)</span>
        <span class="badge ok">CPU-ONLY · APACHE-2.0 · NO LOGS</span>
      </h2>
      <div class="controls" style="margin-top:0; margin-bottom:8px;">
        <span class="muted">Try an unpredictable prompt:</span>
        <button class="chip" type="button" data-prompt="Write a 2-sentence explanation of why speed-of-light latency bounds datacenter geography.">Speed of light</button>
        <button class="chip" type="button" data-prompt="Compute 37 * 41 and show one short step.">Math check</button>
        <button class="chip" type="button" data-prompt="Write a 3-line haiku about an encrypted CPU running in silence.">Haiku</button>
      </div>
      <textarea id="prompt-input" maxlength="600" placeholder="Enter any fresh unpredictable prompt (max 600 chars, never logged)…">Explain in two concise sentences what makes hardware TEE attestation different from trusting a cloud dashboard.</textarea>
      <div class="controls">
        <label class="muted">Max tokens: <strong id="max-tok-label">80</strong>
          <input id="max-tok" type="range" min="16" max="128" value="80" style="vertical-align:middle;" />
        </label>
        <label class="muted">Temp: <strong id="temp-label">0.2</strong>
          <input id="temp" type="range" min="0" max="10" value="2" style="vertical-align:middle;" />
        </label>
        <button id="btn-run" class="primary" type="button">Generate &amp; Sign on CPU TEE</button>
        <span id="run-meta" class="muted mono"></span>
      </div>
      <div id="output-box" class="output-box muted">Completion will appear here after the enclave finishes generating on CPU and signs the post-execution receipt.</div>

      <div id="receipt-panel" class="hidden" style="margin-top:14px;">
        <div class="controls" style="margin-top:0; justify-content:space-between;">
          <strong>Signed Post-Execution Receipt (Browser View — verify independently via CLI/SDK)</strong>
          <div>
            <button id="btn-download-evidence" type="button">⬇ Download Receipt + Evidence JSON</button>
            <a id="link-server-receipt" class="pill" target="_blank" rel="noopener" style="margin-left:6px;">Open Server /v1/receipts/…</a>
          </div>
        </div>
        <div class="kv" id="kv-receipt"></div>
      </div>
    </section>

    <!-- Copy-Paste Independent Clients: Unmodified OpenAI SDK + One-Command CLI -->
    <section class="card" style="margin-bottom:18px;">
      <h2>
        <span>Independent Verification &amp; Official OpenAI SDK Usage</span>
        <span class="badge info">OPEN-SOURCE · FAIL-CLOSED</span>
      </h2>
      <div class="tabs">
        <button class="tab-btn active" type="button" data-pane="pane-cli">1. One-Command Independent CLI (Full TLS 1.3 EKM)</button>
        <button class="tab-btn" type="button" data-pane="pane-sdk-stock">2. Stock Official OpenAI SDK</button>
        <button class="tab-btn" type="button" data-pane="pane-sdk-verify">3. Official OpenAI SDK + Verifying Transport</button>
      </div>

      <div id="pane-cli" class="code-pane">
        <p class="muted" style="margin:0;">Establishes its own real TLS 1.3 socket, exports RFC 8446 §7.5 EKM (<code>EXPORTER-pog-inference-v1</code>), sends a fresh unpredictable nonce, fetches live Google Confidential Space JWKS, and verifies hardware TDX + pinned model + commitments + separate PoG geography without trusting this page:</p>
        <pre id="snippet-cli">cargo run --release --bin pog-cli -- demo-client https://llm.proofofgeography.com \
  --prompt "What is 19 * 23? Answer in one sentence." \
  --out-evidence evidence.json</pre>
      </div>

      <div id="pane-sdk-stock" class="code-pane hidden">
        <p class="muted" style="margin:0;">Works directly with the unmodified official <code>openai</code> Python SDK. Use <code>with_raw_response</code> to inspect the receipt headers returned on the original response:</p>
        <pre>from openai import OpenAI

client = OpenAI(
    base_url="https://llm.proofofgeography.com/v1",
    api_key="pog-public-demo",
)
raw = client.chat.completions.with_raw_response.create(
    model="qwen2.5-0.5b-instruct-q4_k_m",
    messages=[{"role": "user", "content": "Say hello in one sentence."}],
    max_tokens=64,
)
print("Answer:", raw.parse().choices[0].message.content)
print("Receipt ID:", raw.headers.get("x-pog-receipt-id"))
print("Receipt SHA-256:", raw.headers.get("x-pog-receipt-sha256"))
print("Commitment Salt:", raw.headers.get("x-pog-commitment-salt"))</pre>
      </div>

      <div id="pane-sdk-verify" class="code-pane hidden">
        <p class="muted" style="margin:0;">Optional <code>PogVerifyingTransport</code> verifies the exact TLS 1.3 EKM, pinned container digest, hardware Intel TDX OIDC chain, blinded commitments, and separate PoG status on <strong>that very same SDK call</strong> (no second inference):</p>
        <pre id="snippet-sdk-verify">from openai import OpenAI
from sdks.python.pog_openai_verifier import PogVerifiedHttpClient

http_client = PogVerifiedHttpClient(
    expected_image_digest="sha256:&lt;PINNED_CONTAINER_DIGEST&gt;",
    strict=True,
)
client = OpenAI(
    base_url="https://llm.proofofgeography.com/v1",
    api_key="pog-public-demo",
    http_client=http_client,
)
resp = client.chat.completions.create(
    model="qwen2.5-0.5b-instruct-q4_k_m",
    messages=[{"role": "user", "content": "Why does speed of light bound location?"}],
    max_tokens=64,
)
print("Verified answer:", resp.choices[0].message.content)
print("Verification report:", http_client.last_report)</pre>
      </div>

      <table style="margin-top:14px;">
        <thead>
          <tr><th>Verification Check</th><th>Browser UI</th><th>Stock OpenAI SDK</th><th>OpenAI SDK + Verifying Transport / <code>pog-cli</code></th></tr>
        </thead>
        <tbody>
          <tr><td>Standard TLS CA / hostname</td><td>Browser CA store</td><td>httpx/OpenSSL CA store</td><td>Verified + exact leaf cert SHA-256 bound to enclave Ed25519 key</td></tr>
          <tr><td>End-to-end TLS 1.3 EKM (<code>EXPORTER-pog-inference-v1</code>)</td><td>❌ Unavailable in JS</td><td>❌ Not extracted</td><td>✅ Verified on the exact inference TLS 1.3 socket</td></tr>
          <tr><td>Google Confidential Space Intel TDX RS256 OIDC + JWKS</td><td>❌ Must trust page JS</td><td>❌ Not checked</td><td>✅ Independently verified against live Google JWKS + pinned digest</td></tr>
          <tr><td>Blinded SHA-256 request/output commitments + fresh nonce</td><td>⚠️ Client-side JS only</td><td>Headers available via <code>with_raw_response</code></td><td>✅ Verified over exact raw HTTP request &amp; response bytes</td></tr>
          <tr><td>Production multi-cloud hardware PoG quorum</td><td>Displayed (unverified)</td><td>❌ Not checked</td><td>✅ Separately verified (never counts prover or SoftwareDev nodes)</td></tr>
        </tbody>
      </table>
    </section>

    <!-- Attested vs Relay-Only Architecture Diagram -->
    <section class="card">
      <h2>
        <span>Architecture Boundary: Attested Enclave vs. Untrusted Relay/Network</span>
        <span class="badge ok">ZERO EXTERNAL TLS TERMINATION</span>
      </h2>
      <svg viewBox="0 0 980 230" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Attested Intel TDX Enclave vs Untrusted Network Diagram">
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
          </marker>
        </defs>
        <rect x="10" y="30" width="190" height="150" rx="12" fill="#0d1526" stroke="#38bdf8" stroke-width="1.5"/>
        <text x="105" y="58" text-anchor="middle" fill="#e6edf8" font-size="13" font-weight="700">Independent Client</text>
        <text x="105" y="80" text-anchor="middle" fill="#94a3b8" font-size="11">pog-cli / OpenAI SDK</text>
        <text x="105" y="100" text-anchor="middle" fill="#94a3b8" font-size="11">+ PogVerifyingTransport</text>
        <text x="105" y="128" text-anchor="middle" fill="#34d399" font-size="10.5">Extracts own TLS 1.3 EKM</text>
        <text x="105" y="146" text-anchor="middle" fill="#34d399" font-size="10.5">Verifies Google JWKS</text>
        <text x="105" y="164" text-anchor="middle" fill="#34d399" font-size="10.5">Checks PoG Quorum</text>

        <rect x="235" y="55" width="160" height="100" rx="10" fill="#18121e" stroke="#fbbf24" stroke-dasharray="5,4" stroke-width="1.5"/>
        <text x="315" y="84" text-anchor="middle" fill="#fbbf24" font-size="12" font-weight="700">Untrusted Transit</text>
        <text x="315" y="104" text-anchor="middle" fill="#94a3b8" font-size="10.5">Internet / GCP VPC / NIC</text>
        <text x="315" y="122" text-anchor="middle" fill="#fbbf24" font-size="10.5">Relay-only encrypted bytes</text>
        <text x="315" y="140" text-anchor="middle" fill="#fb7185" font-size="10.5">NO TLS termination</text>

        <rect x="430" y="12" width="340" height="205" rx="14" fill="#091a1e" stroke="#34d399" stroke-width="2"/>
        <text x="600" y="35" text-anchor="middle" fill="#34d399" font-size="12.5" font-weight="700">MEASURED INTEL TDX CONFIDENTIAL SPACE</text>
        <text x="600" y="52" text-anchor="middle" fill="#94a3b8" font-size="10.5">FROM scratch · Zero SSH · Zero Shell · Empty cmd_override</text>
        <rect x="448" y="64" width="304" height="34" rx="7" fill="#0d242b" stroke="#38bdf8" stroke-width="1"/>
        <text x="600" y="85" text-anchor="middle" fill="#e6edf8" font-size="11">rustls TLS 1.3 (RAM P-256 + ACME TLS-ALPN-01) + EKM</text>
        <rect x="448" y="106" width="146" height="44" rx="7" fill="#0d242b" stroke="#34d399" stroke-width="1"/>
        <text x="521" y="125" text-anchor="middle" fill="#e6edf8" font-size="11">Demo HTML +</text>
        <text x="521" y="141" text-anchor="middle" fill="#e6edf8" font-size="11">/v1/chat/completions</text>
        <rect x="606" y="106" width="146" height="44" rx="7" fill="#0d242b" stroke="#34d399" stroke-width="1"/>
        <text x="679" y="125" text-anchor="middle" fill="#e6edf8" font-size="11">Candle CPU LLM</text>
        <text x="679" y="141" text-anchor="middle" fill="#94a3b8" font-size="10">Qwen2.5-0.5B Q4_K_M</text>
        <rect x="448" y="158" width="304" height="44" rx="7" fill="#0d242b" stroke="#34d399" stroke-width="1"/>
        <text x="600" y="177" text-anchor="middle" fill="#e6edf8" font-size="11">Nonexportable Ed25519 Key (Receipt Signer + PoG Prover)</text>
        <text x="600" y="193" text-anchor="middle" fill="#94a3b8" font-size="10">Zero prompt/output logs · Blinded SHA-256 commitments</text>

        <rect x="805" y="20" width="165" height="82" rx="10" fill="#0d1526" stroke="#34d399" stroke-width="1.3"/>
        <text x="887" y="46" text-anchor="middle" fill="#34d399" font-size="11.5" font-weight="700">GCP Attestation</text>
        <text x="887" y="65" text-anchor="middle" fill="#94a3b8" font-size="10.5">teeserver.sock OIDC</text>
        <text x="887" y="83" text-anchor="middle" fill="#94a3b8" font-size="10.5">RS256 Intel TDX JWT</text>

        <rect x="805" y="122" width="165" height="88" rx="10" fill="#0d1526" stroke="#fbbf24" stroke-width="1.3"/>
        <text x="887" y="147" text-anchor="middle" fill="#fbbf24" font-size="11.5" font-weight="700">Out-of-Band Anchors</text>
        <text x="887" y="166" text-anchor="middle" fill="#94a3b8" font-size="10.5">Multi-Cloud UDP PoG</text>
        <text x="887" y="183" text-anchor="middle" fill="#94a3b8" font-size="10.5">Separate Geo Status</text>
        <text x="887" y="199" text-anchor="middle" fill="#fbbf24" font-size="10">Never self-anchored</text>

        <line x1="200" y1="105" x2="233" y2="105" stroke="#38bdf8" stroke-width="2" marker-end="url(#arr)"/>
        <line x1="395" y1="105" x2="428" y2="105" stroke="#38bdf8" stroke-width="2" marker-end="url(#arr)"/>
        <line x1="770" y1="62" x2="803" y2="62" stroke="#34d399" stroke-width="1.6" marker-end="url(#arr)"/>
        <line x1="770" y1="168" x2="803" y2="168" stroke="#fbbf24" stroke-width="1.6" marker-end="url(#arr)"/>
      </svg>
    </section>
  </main>

  <script>
    let latestEvidence = null;
    function randomHex(bytes) {
      const a = new Uint8Array(bytes);
      crypto.getRandomValues(a);
      return Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
    }
    function esc(s) {
      return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    async function loadInfo() {
      try {
        const res = await fetch('/v1/info');
        const info = await res.json();
        const teeBadge = document.getElementById('badge-tee');
        teeBadge.textContent = info.hardware_tee_active ? 'INTEL TDX ACTIVE' : 'LOCAL TEST MODE';
        teeBadge.className = 'badge ' + (info.hardware_tee_active ? 'ok' : 'warn');
        document.getElementById('kv-tee').innerHTML = `
          <div class="k">TEE Vendor / Mode</div><div class="v">${esc(info.tee_vendor)} (${esc(info.tls_issuer)})</div>
          <div class="k">Container Digest</div><div class="v">${esc(info.container_image_digest || 'not-in-confidential-space')}</div>
          <div class="k">Pinned Model</div><div class="v">${esc(info.model_runtime.model_id)} (${esc(info.model_runtime.license)})</div>
          <div class="k">Weights SHA-256</div><div class="v">${esc(info.model_runtime.weights_sha256_hex)}</div>
          <div class="k">Enclave Ed25519 Key</div><div class="v">${esc(info.prover_pk_hex)}</div>
          <div class="k">TLS Leaf SHA-256</div><div class="v">${esc(info.tls_leaf_cert_sha256_hex)}</div>
          <div class="k">Git Revision</div><div class="v">${esc(info.model_runtime.git_revision)}</div>
        `;
        const geoBadge = document.getElementById('badge-geo');
        if (info.production_geo_quorum_available) {
          geoBadge.textContent = 'PROD QUORUM READY';
          geoBadge.className = 'badge ok';
        } else {
          geoBadge.textContent = 'UNPROVEN (DIAGNOSTIC ONLY)';
          geoBadge.className = 'badge warn';
        }
        document.getElementById('kv-geo').innerHTML = `
          <div class="k">Production Quorum</div><div class="v">${info.production_geo_quorum_available ? 'Hardware TEE anchor bundle attached' : 'Insufficient production hardware TEE anchors (0/42 published nodes are hardware TEEs yet — location NOT claimed)'}</div>
          <div class="k">Cloud VM Metadata</div><div class="v">${esc(info.gcp_cloud_metadata_zone || 'none')} (cloud metadata only — NOT speed-of-light proof)</div>
          <div class="k">Self-Anchoring</div><div class="v">Forbidden (prover key excluded from anchor quorum)</div>
        `;
        const diags = info.diagnostic_anchor_rtts || [];
        document.getElementById('diag-table-wrap').innerHTML = diags.length
          ? '<table><thead><tr><th>Anchor (Diagnostic Only)</th><th>Cloud</th><th>City</th><th>Min RTT</th></tr></thead><tbody>' +
            diags.map(d => `<tr><td class="mono">${esc(d.anchor_id)}</td><td>${esc(d.cloud_provider)}</td><td>${esc(d.city)}</td><td class="mono">${Number(d.rtt_min_ms).toFixed(2)} ms</td></tr>`).join('') +
            '</tbody></table>'
          : 'No diagnostic observations recorded yet.';
        if (info.container_image_digest && info.container_image_digest.startsWith('sha256:')) {
          document.getElementById('snippet-cli').textContent =
            `cargo run --release --bin pog-cli -- demo-client ${window.location.origin} \\\n  --expected-image-digest ${info.container_image_digest} \\\n  --prompt "What is 19 * 23? Answer in one sentence." \\\n  --out-evidence evidence.json`;
          const sdkEl = document.getElementById('snippet-sdk-verify');
          if (sdkEl) {
            sdkEl.textContent =
`from openai import OpenAI
from sdks.python.pog_openai_verifier import PogVerifiedHttpClient

http_client = PogVerifiedHttpClient(
    expected_image_digest="${info.container_image_digest}",
    strict=True,
)
client = OpenAI(
    base_url="${window.location.origin}/v1",
    api_key="pog-public-demo",
    http_client=http_client,
)
resp = client.chat.completions.create(
    model="qwen2.5-0.5b-instruct-q4_k_m",
    messages=[{"role": "user", "content": "Why does speed of light bound location?"}],
    max_tokens=64,
)
print("Verified answer:", resp.choices[0].message.content)
print("Verification report:", http_client.last_report)`;
          }
        }
      } catch (e) {
        document.getElementById('kv-tee').innerHTML = `<div class="k">Error</div><div class="v">${esc(e)}</div>`;
      }
    }

    document.querySelectorAll('.chip[data-prompt]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('prompt-input').value = btn.dataset.prompt;
      });
    });
    document.getElementById('max-tok').addEventListener('input', e => {
      document.getElementById('max-tok-label').textContent = e.target.value;
    });
    document.getElementById('temp').addEventListener('input', e => {
      document.getElementById('temp-label').textContent = (Number(e.target.value) / 10).toFixed(1);
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.code-pane').forEach(p => p.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.pane).classList.remove('hidden');
      });
    });

    document.getElementById('btn-run').addEventListener('click', async () => {
      const btn = document.getElementById('btn-run');
      const outBox = document.getElementById('output-box');
      const meta = document.getElementById('run-meta');
      const promptText = document.getElementById('prompt-input').value.trim();
      if (!promptText) return;
      btn.disabled = true;
      outBox.classList.add('muted');
      outBox.textContent = 'Generating locally on enclave CPU (no GPU, no external API)…';
      meta.textContent = '';

      const clientNonce = randomHex(32);
      const reqObj = {
        model: 'qwen2.5-0.5b-instruct-q4_k_m',
        messages: [{ role: 'user', content: promptText }],
        max_tokens: Number(document.getElementById('max-tok').value),
        temperature: Number(document.getElementById('temp').value) / 10,
      };
      const rawReq = JSON.stringify(reqObj);
      const t0 = performance.now();
      try {
        const res = await fetch('/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-PoG-Client-Nonce': clientNonce,
          },
          body: rawReq,
        });
        const rawResp = await res.text();
        const elapsedMs = performance.now() - t0;
        if (!res.ok) {
          outBox.textContent = `HTTP ${res.status}: ${rawResp}`;
          return;
        }
        const parsed = JSON.parse(rawResp);
        const answer = parsed.choices?.[0]?.message?.content ?? '';
        const compToks = parsed.usage?.completion_tokens ?? 0;
        const tps = elapsedMs > 0 ? (compToks / (elapsedMs / 1000)).toFixed(1) : '—';
        outBox.classList.remove('muted');
        outBox.textContent = answer;
        meta.textContent = `${(elapsedMs / 1000).toFixed(2)}s · ${compToks} tokens (${tps} tok/s CPU)`;

        const receiptId = res.headers.get('x-pog-receipt-id') || '';
        const receiptSha = res.headers.get('x-pog-receipt-sha256') || '';
        const salt = res.headers.get('x-pog-commitment-salt') || '';
        const evRes = await fetch(`/v1/receipts/${encodeURIComponent(receiptId)}`);
        const serverEvidence = await evRes.json();

        latestEvidence = {
          ...serverEvidence,
          browser_view_note: 'Captured in browser JS — ordinary browsers cannot verify TLS 1.3 EKM; run pog-cli demo-client or PogVerifiedHttpClient for independent end-to-end TLS verification.',
          browser_captured_fields: {
            endpoint_url: window.location.origin + '/v1/chat/completions',
            client_nonce_hex: clientNonce,
            commitment_salt_hex: salt,
            raw_request_body: rawReq,
            raw_response_body: rawResp,
          },
        };

        document.getElementById('receipt-panel').classList.remove('hidden');
        document.getElementById('link-server-receipt').href = `/v1/receipts/${encodeURIComponent(receiptId)}`;
        const r = serverEvidence.receipt || {};
        document.getElementById('kv-receipt').innerHTML = `
          <div class="k">Receipt ID</div><div class="v">${esc(receiptId)}</div>
          <div class="k">Receipt SHA-256</div><div class="v">${esc(receiptSha)}</div>
          <div class="k">Client Nonce</div><div class="v">${esc(clientNonce)}</div>
          <div class="k">Commitment Salt</div><div class="v">${esc(salt)} (returned ONLY over your TLS session; NOT stored on server)</div>
          <div class="k">Request Commitment</div><div class="v">${esc(r.request_commitment_hex)}</div>
          <div class="k">Output Commitment</div><div class="v">${esc(r.output_commitment_hex)}</div>
          <div class="k">TLS EKM (Server View)</div><div class="v">${esc(r.tls_session_binding?.tls_exporter_ekm_hex)} (verify via CLI/SDK!)</div>
          <div class="k">Enclave Signature</div><div class="v">${esc(r.prover_signature_hex)}</div>
        `;
      } catch (e) {
        outBox.textContent = 'Request failed: ' + e;
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById('btn-download-evidence').addEventListener('click', () => {
      if (!latestEvidence) return;
      const blob = new Blob([JSON.stringify(latestEvidence, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `pog-llm-evidence-${latestEvidence.receipt?.receipt_id || 'receipt'}.json`;
      a.click();
    });

    loadInfo();
  </script>
</body>
</html>
"##;
