/* ═══════════════════════════════════════════════════════
   TrustShield (ShieldAI) - Main JavaScript
═══════════════════════════════════════════════════════ */

// ─── Utility ─────────────────────────────────────────────────────────────────
function showLoading(el) { el.classList.add("show"); }
function hideLoading(el) { el.classList.remove("show"); }
function showResult(el) { el.classList.add("show"); }
function hideResult(el) { el.classList.remove("show"); }

function getRiskClass(level) {
  if (level === "HIGH") return "risk-high";
  if (level === "MEDIUM") return "risk-medium";
  return "risk-low";
}

function getBadgeClass(level) {
  if (level === "HIGH") return "badge-high";
  if (level === "MEDIUM") return "badge-medium";
  return "badge-low";
}

function getFillClass(level) {
  if (level === "HIGH") return "fill-high";
  if (level === "MEDIUM") return "fill-medium";
  return "fill-low";
}

function getRiskEmoji(level) {
  if (level === "HIGH") return "🔴";
  if (level === "MEDIUM") return "🟡";
  return "🟢";
}

// ─── Login Page ───────────────────────────────────────────────────────────────
(function initLogin() {
  const loginForm = document.getElementById("loginForm");
  if (!loginForm) return;

  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
    });
  });

  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const errorMsg = document.getElementById("errorMsg");
    const submitBtn = document.getElementById("submitBtn");

    errorMsg.classList.remove("show");

    if (!name || !email) {
      errorMsg.textContent = "Please fill in all fields.";
      errorMsg.classList.add("show");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Securing connection...";

    try {
      const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email })
      });
      const data = await res.json();

      if (data.success) {
        submitBtn.textContent = "✓ Redirecting...";
        window.location.href = data.redirect;
      } else {
        errorMsg.textContent = data.message;
        errorMsg.classList.add("show");
        submitBtn.disabled = false;
        submitBtn.textContent = "Enter TrustShield";
      }
    } catch (err) {
      errorMsg.textContent = "Connection error. Please try again.";
      errorMsg.classList.add("show");
      submitBtn.disabled = false;
      submitBtn.textContent = "Enter TrustShield";
    }
  });
})();


// ─── URL Analyzer ────────────────────────────────────────────────────────────
(function initUrlAnalyzer() {
  const form = document.getElementById("urlForm");
  if (!form) return;

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const urlInput = document.getElementById("urlInput").value.trim();
    const loading = document.getElementById("urlLoading");
    const result = document.getElementById("urlResult");
    const btn = document.getElementById("urlBtn");

    if (!urlInput) return;

    hideResult(result);
    showLoading(loading);
    btn.disabled = true;

    try {
      const res = await fetch("/api/analyze-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput })
      });
      const data = await res.json();

      if (data.error) {
        alert("Error: " + data.error);
        return;
      }

      renderRiskResult(data, "urlResult", {
        title: `${getRiskEmoji(data.risk_level)} URL Risk Analysis`,
        score: data.risk_score,
        level: data.risk_level,
        flags: data.flags,
        advice: data.advice,
        extra: `<p style="font-size:13px; color:var(--text-muted); margin-bottom:8px;">Analyzed: <code style="color:var(--accent)">${escapeHtml(data.url_analyzed)}</code></p>`
      });

      showResult(result);
    } catch (err) {
      alert("An error occurred. Please try again.");
    } finally {
      hideLoading(loading);
      btn.disabled = false;
    }
  });
})();


// ─── Text Analyzer ────────────────────────────────────────────────────────────
(function initTextAnalyzer() {
  const form = document.getElementById("textForm");
  if (!form) return;

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const textInput = document.getElementById("textInput").value.trim();
    const loading = document.getElementById("textLoading");
    const result = document.getElementById("textResult");
    const btn = document.getElementById("textBtn");

    if (!textInput) return;

    hideResult(result);
    showLoading(loading);
    btn.disabled = true;

    try {
      const res = await fetch("/api/analyze-text", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: textInput })
      });
      const data = await res.json();

      if (data.error) {
        alert("Error: " + data.error);
        return;
      }

      // Build scam type tags
      let tagsHtml = "";
      if (data.scam_types && data.scam_types[0] !== "None detected") {
        tagsHtml = `<div class="result-section">
          <h4>Detected Scam Types</h4>
          <div class="scam-tags">${data.scam_types.map(t => `<span class="scam-tag">⚠ ${t}</span>`).join("")}</div>
        </div>`;
      }

      renderRiskResult(data, "textResult", {
        title: `${getRiskEmoji(data.risk_level)} Message Risk Analysis`,
        score: data.risk_score,
        level: data.risk_level,
        flags: data.flags,
        advice: data.advice,
        extra: tagsHtml
      });

      showResult(result);
    } catch (err) {
      alert("An error occurred. Please try again.");
    } finally {
      hideLoading(loading);
      btn.disabled = false;
    }
  });

  // Sample buttons
  const samples = document.querySelectorAll(".sample-btn");
  samples.forEach(btn => {
    btn.addEventListener("click", () => {
      document.getElementById("textInput").value = btn.dataset.text;
    });
  });
})();


// ─── Doctor Verifier ──────────────────────────────────────────────────────────
(function initDoctorVerify() {
  const form = document.getElementById("doctorForm");
  if (!form) return;

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const query = document.getElementById("doctorInput").value.trim();
    const loading = document.getElementById("doctorLoading");
    const result = document.getElementById("doctorResult");
    const btn = document.getElementById("doctorBtn");

    if (!query) return;

    result.innerHTML = "";
    result.className = "verified-card";
    showLoading(loading);
    btn.disabled = true;

    try {
      const res = await fetch("/api/verify-doctor", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query })
      });
      const data = await res.json();

      let html = "";

      if (data.verified === true) {
        html = `
          <div class="verify-badge">✓ VERIFIED DOCTOR</div>
          <p style="color:var(--text-secondary); font-size:14px; margin-bottom:16px;">${data.message}</p>
          <div class="doctor-info">
            <div class="info-item"><label>Doctor Name</label><div class="value">${escapeHtml(data.name)}</div></div>
            <div class="info-item"><label>Hospital</label><div class="value">${escapeHtml(data.hospital)}</div></div>
            <div class="info-item"><label>Specialty</label><div class="value">${escapeHtml(data.specialty)}</div></div>
            <div class="info-item"><label>MCI Registration ID</label><div class="value" style="font-family:var(--font-mono)">${escapeHtml(data.id)}</div></div>
          </div>`;
        result.classList.add("show");
      } else if (data.verified === "partial") {
        html = `<div class="verify-badge" style="background:var(--warning); color:#111">⚠ PARTIAL MATCHES</div>
          <p style="color:var(--text-secondary); font-size:14px; margin-bottom:16px;">${data.message}</p>`;
        data.matches.forEach(m => {
          html += `<div style="background:var(--bg-secondary); border:1px solid var(--border); border-radius:8px; padding:12px 16px; margin-bottom:8px;">
            <strong>${escapeHtml(m.name)}</strong> &mdash; ${escapeHtml(m.hospital)} &mdash; ${escapeHtml(m.specialty)}
          </div>`;
        });
        result.style.background = "var(--warning-bg)";
        result.style.borderColor = "rgba(255,165,2,0.3)";
        result.classList.add("show");
      } else {
        html = `<div class="verify-badge not-verify-badge">✗ NOT FOUND</div>
          <p style="color:var(--text-secondary); font-size:14px; margin-top:12px;">${data.message}</p>
          <div class="tips-box" style="margin-top:16px;">
            <h4>How to verify a doctor</h4>
            <ul>
              <li>Visit the MCI (Medical Council of India) website: mciindia.org</li>
              <li>Call the hospital directly on their official number</li>
              <li>Ask to see the doctor's registration certificate</li>
            </ul>
          </div>`;
        result.classList.add("not-verified-card");
        result.classList.add("show");
      }

      result.innerHTML = html;
    } catch (err) {
      alert("An error occurred. Please try again.");
    } finally {
      hideLoading(loading);
      btn.disabled = false;
    }
  });
})();


// ─── Voice Detection ──────────────────────────────────────────────────────────
(function initVoiceDetect() {
  const recordBtn = document.getElementById("recordBtn");
  if (!recordBtn) return;

  const transcriptBox = document.getElementById("transcriptBox");
  const analyzeBtn = document.getElementById("analyzeVoiceBtn");
  const loading = document.getElementById("voiceLoading");
  const result = document.getElementById("voiceResult");
  const statusDot = document.getElementById("recordingDot");
  const statusText = document.getElementById("recordingStatus");

  let recognition = null;
  let isRecording = false;
  let fullTranscript = "";

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    recordBtn.disabled = true;
    recordBtn.textContent = "⚠ Browser not supported";
    transcriptBox.textContent = "Your browser does not support Speech Recognition. Please use Chrome or Edge.";
    return;
  }

  recognition = new SpeechRecognition();
  recognition.lang = "en-IN";
  recognition.continuous = true;
  recognition.interimResults = true;

  recognition.onresult = function (event) {
    let interimTranscript = "";
    let finalTranscript = "";
    for (let i = event.resultIndex; i < event.results.length; i++) {
      const transcript = event.results[i][0].transcript;
      if (event.results[i].isFinal) {
        finalTranscript += transcript + " ";
      } else {
        interimTranscript += transcript;
      }
    }
    fullTranscript += finalTranscript;
    transcriptBox.textContent = (fullTranscript + interimTranscript) || "Listening...";
    transcriptBox.style.fontStyle = "normal";
    transcriptBox.style.color = "var(--text-primary)";
  };

  recognition.onerror = function (event) {
    statusText.textContent = "Error: " + event.error;
    stopRecording();
  };

  recognition.onend = function () {
    if (isRecording) recognition.start();
  };

  function startRecording() {
    fullTranscript = "";
    transcriptBox.textContent = "Listening... speak now";
    transcriptBox.style.fontStyle = "italic";
    transcriptBox.style.color = "var(--text-secondary)";
    isRecording = true;
    recordBtn.classList.add("recording");
    recordBtn.innerHTML = "⏹ Stop Recording";
    statusDot.classList.add("active");
    statusText.textContent = "Recording...";
    recognition.start();
  }

  function stopRecording() {
    isRecording = false;
    recognition.stop();
    recordBtn.classList.remove("recording");
    recordBtn.innerHTML = "🎙 Start Recording";
    statusDot.classList.remove("active");
    statusText.textContent = "Ready";
    if (fullTranscript.trim()) {
      analyzeBtn.disabled = false;
    }
  }

  recordBtn.addEventListener("click", () => {
    if (isRecording) { stopRecording(); } else { startRecording(); }
  });

  analyzeBtn.addEventListener("click", async function () {
    const text = fullTranscript.trim();
    if (!text) return;

    hideResult(result);
    showLoading(loading);
    analyzeBtn.disabled = true;

    try {
      const res = await fetch("/api/analyze-text", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });
      const data = await res.json();

      let tagsHtml = "";
      if (data.scam_types && data.scam_types[0] !== "None detected") {
        tagsHtml = `<div class="result-section">
          <h4>Detected Scam Types</h4>
          <div class="scam-tags">${data.scam_types.map(t => `<span class="scam-tag">⚠ ${t}</span>`).join("")}</div>
        </div>`;
      }

      renderRiskResult(data, "voiceResult", {
        title: `${getRiskEmoji(data.risk_level)} Voice Analysis Result`,
        score: data.risk_score,
        level: data.risk_level,
        flags: data.flags,
        advice: data.advice,
        extra: tagsHtml
      });

      showResult(result);
    } catch (err) {
      alert("An error occurred. Please try again.");
    } finally {
      hideLoading(loading);
      analyzeBtn.disabled = false;
    }
  });
})();


// ─── Chatbot ─────────────────────────────────────────────────────────────────
(function initChatbot() {
  const chatMessages = document.getElementById("chatMessages");
  const chatInput = document.getElementById("chatInput");
  const sendBtn = document.getElementById("sendBtn");
  if (!chatMessages) return;

  function addMessage(text, sender) {
    const msg = document.createElement("div");
    msg.className = `message ${sender}`;
    const avatar = sender === "bot" ? "🛡" : "👤";
    msg.innerHTML = `
      <div class="message-avatar">${avatar}</div>
      <div class="message-text">${escapeHtml(text)}</div>`;
    chatMessages.appendChild(msg);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  async function sendMessage(text) {
    if (!text.trim()) return;
    addMessage(text, "user");
    chatInput.value = "";

    try {
      const res = await fetch("/api/chatbot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text })
      });
      const data = await res.json();
      addMessage(data.response, "bot");
    } catch (err) {
      addMessage("Sorry, I couldn't connect. Please try again.", "bot");
    }
  }

  sendBtn.addEventListener("click", () => sendMessage(chatInput.value));

  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage(chatInput.value);
  });

  // Quick chips
  document.querySelectorAll(".chip").forEach(chip => {
    chip.addEventListener("click", () => sendMessage(chip.textContent));
  });
})();


// ─── Shared Result Renderer ───────────────────────────────────────────────────
function renderRiskResult(data, containerId, opts) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.className = `result-panel ${getRiskClass(opts.level)} show`;

  const flagsHtml = (opts.flags || []).map(f => `<li>${escapeHtml(f)}</li>`).join("");
  const adviceHtml = (opts.advice || []).map(a => `<li>${escapeHtml(a)}</li>`).join("");

  container.innerHTML = `
    <div class="risk-badge ${getBadgeClass(opts.level)}">${getRiskEmoji(opts.level)} ${opts.level} RISK</div>
    <h3 style="font-size:16px; margin-bottom:4px;">${opts.title}</h3>
    <div class="risk-meter">
      <div class="risk-meter-fill ${getFillClass(opts.level)}" style="width:${opts.score}%"></div>
    </div>
    <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">Risk Score: ${opts.score}/100</p>
    ${opts.extra || ""}
    ${flagsHtml ? `<div class="result-section"><h4>⚑ Warning Signals</h4><ul class="flags-list">${flagsHtml}</ul></div>` : ""}
    ${adviceHtml ? `<div class="result-section" style="margin-top:16px;"><h4>→ What to do</h4><ul class="advice-list">${adviceHtml}</ul></div>` : ""}
  `;
}


// ─── Escape HTML ─────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (typeof str !== "string") return str;
  return str.replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
}