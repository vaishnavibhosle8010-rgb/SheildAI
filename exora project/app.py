from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import re
import urllib.parse

app = Flask(__name__)
app.secret_key = "trustshield_secret_2024"

# ─── Trusted Doctors List ───────────────────────────────────────────────────
TRUSTED_DOCTORS = {
    "dr. rajesh kumar": {"hospital": "AIIMS Delhi", "specialty": "Cardiology", "id": "MCI-12345"},
    "dr. priya sharma": {"hospital": "Apollo Hospitals", "specialty": "General Medicine", "id": "MCI-23456"},
    "dr. anil mehta": {"hospital": "Fortis Healthcare", "specialty": "Neurology", "id": "MCI-34567"},
    "dr. sunita rao": {"hospital": "Manipal Hospitals", "specialty": "Pediatrics", "id": "MCI-45678"},
    "dr. vikram singh": {"hospital": "Max Healthcare", "specialty": "Orthopedics", "id": "MCI-56789"},
    "dr. kavitha nair": {"hospital": "Narayana Health", "specialty": "Oncology", "id": "MCI-67890"},
    "dr. suresh patel": {"hospital": "Medanta", "specialty": "Gastroenterology", "id": "MCI-78901"},
    "dr. anitha reddy": {"hospital": "Yashoda Hospitals", "specialty": "Gynecology", "id": "MCI-89012"},
    "dr. ravi krishnan": {"hospital": "Care Hospitals", "specialty": "Urology", "id": "MCI-90123"},
    "dr. meena joshi": {"hospital": "NIMHANS", "specialty": "Psychiatry", "id": "MCI-01234"},
}

# ─── Scam Keywords ───────────────────────────────────────────────────────────
URGENCY_WORDS = [
    "urgent", "immediately", "expire", "expires", "expiring", "last chance",
    "act now", "hurry", "limited time", "deadline", "warning", "alert",
    "suspended", "blocked", "deactivated", "verify now", "confirm now",
    "within 24 hours", "within 48 hours", "do not ignore", "final notice"
]

OTP_WORDS = [
    "otp", "one time password", "verification code", "pin", "cvv",
    "share your otp", "send otp", "enter otp", "provide otp",
    "bank otp", "upi pin", "atm pin", "card number", "account number"
]

MONEY_WORDS = [
    "prize", "winner", "won", "lottery", "reward", "cashback",
    "refund", "payment", "transfer money", "send money", "pay now",
    "click to claim", "congratulations you have won", "free money",
    "investment", "double your money", "guaranteed returns", "loan approved"
]

IMPERSONATION_WORDS = [
    "rbi", "income tax", "police", "cbi", "trai", "government",
    "bank of india", "sbi", "hdfc", "icici", "aadhaar", "pan card",
    "income tax department", "customs department", "cyber cell",
    "supreme court", "high court", "enforcement directorate"
]

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "bank", "secure", "update", "confirm",
    "account", "password", "credential", "signin", "authenticate",
    "paypal", "paytm", "gpay", "phonepe", "upi", "aadhaar", "pan",
    "free", "prize", "winner", "claim", "reward"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"]

KNOWN_SCAM_PATTERNS = [
    r"\d{1,3}-\d{1,3}-\d{4,}",  # fake phone numbers with dashes
    r"bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly",  # URL shorteners
]


# ─── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    if not name or not email:
        return jsonify({"success": False, "message": "Name and email are required."})
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return jsonify({"success": False, "message": "Please enter a valid email address."})
    session["user"] = {"name": name, "email": email}
    return jsonify({"success": True, "redirect": "/dashboard"})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=session["user"])


@app.route("/url-analyzer")
def url_analyzer():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("url_analyzer.html", user=session["user"])


@app.route("/text-analyzer")
def text_analyzer():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("text_analyzer.html", user=session["user"])


@app.route("/doctor-verify")
def doctor_verify():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("doctor_verify.html", user=session["user"])


@app.route("/voice-detect")
def voice_detect():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("voice_detect.html", user=session["user"])


@app.route("/chatbot")
def chatbot():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("chatbot.html", user=session["user"])


# ─── API: URL Analysis ────────────────────────────────────────────────────────
@app.route("/api/analyze-url", methods=["POST"])
def analyze_url():
    data = request.get_json()
    url = data.get("url", "").strip().lower()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http"):
        url = "http://" + url

    risk_score = 0
    flags = []
    advice = []

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        path = parsed.path

        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                risk_score += 35
                flags.append(f"Suspicious domain extension '{tld}' — commonly used in scam sites")

        # Check URL length
        if len(url) > 100:
            risk_score += 15
            flags.append("Unusually long URL — scammers hide malicious links in long addresses")

        # Check for IP address instead of domain
        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            risk_score += 40
            flags.append("URL uses an IP address instead of a domain name — very suspicious")

        # Check for suspicious keywords in URL
        keyword_hits = []
        full_url_lower = url.lower()
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in full_url_lower:
                keyword_hits.append(kw)

        if keyword_hits:
            risk_score += min(len(keyword_hits) * 10, 40)
            flags.append(f"Suspicious keywords found in URL: {', '.join(keyword_hits[:5])}")

        # Check for URL shorteners
        for pattern in KNOWN_SCAM_PATTERNS:
            if re.search(pattern, url):
                risk_score += 20
                flags.append("URL shortener detected — true destination is hidden")

        # Check for multiple subdomains (e.g., sbi.bank-secure.verify.tk)
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            risk_score += 20
            flags.append("Excessive subdomains — scammers use this to fake legitimate sites")

        # Check for lookalike domains
        lookalikes = ["sbi", "hdfc", "icici", "paytm", "gpay", "phonepe", "aadhaar", "uidai", "incometax", "rbi"]
        for la in lookalikes:
            if la in domain and not domain.endswith(f"{la}.gov.in") and not domain.endswith(f"{la}.com"):
                risk_score += 30
                flags.append(f"Domain impersonates '{la.upper()}' — may be a phishing site")

        # Check for HTTPS
        if not url.startswith("https"):
            risk_score += 10
            flags.append("Site does not use HTTPS — your data is not encrypted")

        risk_score = min(risk_score, 100)

        if risk_score >= 60:
            risk_level = "HIGH"
            advice = [
                "Do NOT click this link or enter any personal information",
                "Do NOT share OTP, password, or bank details on this site",
                "Report this URL to cybercrime.gov.in",
                "If you already visited, change your passwords immediately"
            ]
        elif risk_score >= 30:
            risk_level = "MEDIUM"
            advice = [
                "Be very careful before proceeding",
                "Do NOT enter your bank or payment details",
                "Verify the website by calling the official number",
                "Look for the padlock icon and correct spelling of the domain"
            ]
        else:
            risk_level = "LOW"
            flags = flags or ["No major red flags detected"]
            advice = [
                "Still be cautious online",
                "Never share your OTP or PIN with anyone",
                "Bookmark official sites to avoid lookalikes"
            ]

    except Exception as e:
        return jsonify({"error": "Invalid URL format"}), 400

    return jsonify({
        "risk_level": risk_level,
        "risk_score": risk_score,
        "flags": flags,
        "advice": advice,
        "url_analyzed": url
    })


# ─── API: Text Analysis ───────────────────────────────────────────────────────
@app.route("/api/analyze-text", methods=["POST"])
def analyze_text():
    data = request.get_json()
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    text_lower = text.lower()
    risk_score = 0
    scam_types = []
    flags = []
    advice = []

    # Check urgency
    urgency_hits = [w for w in URGENCY_WORDS if w in text_lower]
    if urgency_hits:
        risk_score += min(len(urgency_hits) * 12, 35)
        scam_types.append("Urgency Scam")
        flags.append(f"Urgency language detected: '{urgency_hits[0]}' — scammers create panic to rush you")

    # Check OTP requests
    otp_hits = [w for w in OTP_WORDS if w in text_lower]
    if otp_hits:
        risk_score += 40
        scam_types.append("OTP/Credential Theft")
        flags.append(f"OTP or credential request detected — NO legitimate bank or service asks for your OTP")

    # Check money-related words
    money_hits = [w for w in MONEY_WORDS if w in text_lower]
    if money_hits:
        risk_score += min(len(money_hits) * 15, 35)
        scam_types.append("Financial Scam / Fake Prize")
        flags.append(f"Money-related scam language: '{money_hits[0]}' — fake rewards are a classic trick")

    # Check impersonation
    imp_hits = [w for w in IMPERSONATION_WORDS if w in text_lower]
    if imp_hits:
        risk_score += 30
        scam_types.append("Government / Bank Impersonation")
        flags.append(f"Impersonates authority: '{imp_hits[0].upper()}' — scammers pretend to be officials")

    # Check for links in text
    urls_in_text = re.findall(r"http[s]?://\S+|www\.\S+", text)
    if urls_in_text:
        risk_score += 15
        flags.append("Contains links — suspicious links are used to steal information")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
        advice = [
            "This message shows strong signs of being a SCAM",
            "Do NOT reply, click any link, or call any number in this message",
            "Do NOT share your OTP, PIN, or bank details",
            "Block the sender and report to cybercrime.gov.in or call 1930"
        ]
    elif risk_score >= 25:
        risk_level = "MEDIUM"
        advice = [
            "This message has suspicious elements — be careful",
            "Verify by calling the official number of the organization",
            "Do not click links or share personal information",
            "When in doubt, ask a trusted family member"
        ]
    else:
        risk_level = "LOW"
        flags = flags or ["No major scam patterns detected in this message"]
        advice = [
            "Message appears relatively safe, but stay alert",
            "Remember: banks never ask for OTP over phone/SMS",
            "If unsure, always verify with the official source"
        ]

    if not scam_types:
        scam_types = ["None detected"]

    return jsonify({
        "risk_level": risk_level,
        "risk_score": risk_score,
        "scam_types": scam_types,
        "flags": flags,
        "advice": advice
    })


# ─── API: Doctor Verification ─────────────────────────────────────────────────
@app.route("/api/verify-doctor", methods=["POST"])
def verify_doctor():
    data = request.get_json()
    query = data.get("query", "").strip().lower()
    if not query:
        return jsonify({"error": "No doctor name provided"}), 400

    # Exact match
    if query in TRUSTED_DOCTORS:
        doc = TRUSTED_DOCTORS[query]
        return jsonify({
            "verified": True,
            "name": query.title(),
            "hospital": doc["hospital"],
            "specialty": doc["specialty"],
            "id": doc["id"],
            "message": "This doctor is verified in our database."
        })

    # Partial match
    matches = []
    for name, info in TRUSTED_DOCTORS.items():
        if query in name or any(q in name for q in query.split()):
            matches.append({"name": name.title(), **info})

    if matches:
        return jsonify({
            "verified": "partial",
            "matches": matches,
            "message": f"Found {len(matches)} possible match(es). Please verify carefully."
        })

    return jsonify({
        "verified": False,
        "message": "This doctor was NOT found in our verified database. This does NOT necessarily mean they are fraudulent — our database is limited. Always verify credentials directly with the hospital."
    })


# ─── API: Chatbot ─────────────────────────────────────────────────────────────
CHATBOT_RESPONSES = {
    "otp": "🔐 Never share your OTP with anyone — not even bank employees! Your OTP is like the key to your house. Anyone who asks for it is a scammer.",
    "phishing": "🎣 Phishing is when scammers send fake emails/messages pretending to be your bank or government. They want your passwords. Always check the sender's email address carefully.",
    "url": "🔗 Before clicking any link: check if it starts with 'https', look for spelling mistakes in the website name, and never click links sent by unknown senders.",
    "lottery": "🎰 You did NOT win a lottery you didn't enter! Fake lottery scams are very common in India. They ask for a 'processing fee' first. Never pay it — it's a scam.",
    "call": "📞 If someone calls claiming to be from RBI, Income Tax, or Police and asks for money or OTP — it's a SCAM. Government agencies never call asking for money.",
    "upi": "💳 UPI scams: Scammers send a 'collect request' asking you to enter your PIN to RECEIVE money. You never need your PIN to receive — only to send. Never enter PIN for incoming requests.",
    "aadhaar": "🪪 Your Aadhaar number is sensitive. Never share it with unknown people. Official uses require your consent. Report misuse at uidai.gov.in.",
    "investment": "📈 Guaranteed high returns are ALWAYS a scam. No legitimate investment guarantees profit. Be very careful with unknown apps or people promising to 'double your money'.",
    "report": "🚨 To report a scam in India: Call 1930 (National Cyber Crime Helpline) or visit cybercrime.gov.in. You can also report on the TRAI DND app.",
    "safe": "✅ To stay safe online: Use strong passwords, enable 2-step verification, never share OTP, avoid clicking unknown links, and always verify before paying.",
    "hello": "👋 Hello! I'm ShieldBot, your scam protection assistant. Ask me about OTP scams, phishing, fake calls, UPI fraud, or how to stay safe online!",
    "hi": "👋 Hi there! I'm here to help you stay safe from scams. What would you like to know?",
    "help": "🤝 I can help you with:\n• OTP scams\n• Phishing emails & messages\n• Fake lottery/prize scams\n• Fraudulent calls\n• UPI payment scams\n• How to report cybercrime\n\nJust ask me anything!",
    "scam": "⚠️ A scam is when someone tries to cheat you out of money or personal information using tricks. Common Indian scams: fake bank calls, lottery fraud, job scams, and impersonation of government officials.",
    "bank": "🏦 Your real bank will NEVER ask for your ATM PIN, CVV, OTP, or password over phone/SMS/email. If someone claiming to be your bank asks — hang up and call your bank's official number.",
    "job": "💼 Fake job scams: They offer high-paying jobs and ask for a 'registration fee' or 'training fee'. Legitimate companies never charge you to apply. Don't pay!",
    "default": "🤔 I'm not sure about that specific topic, but I'm here to help with scam-related questions! Try asking about: OTP scams, phishing, fake calls, UPI fraud, lottery scams, or how to report cybercrime."
}

@app.route("/api/chatbot", methods=["POST"])
def chatbot_api():
    data = request.get_json()
    message = data.get("message", "").strip().lower()
    if not message:
        return jsonify({"response": "Please type a message."})

    # Find best matching response
    for keyword, response in CHATBOT_RESPONSES.items():
        if keyword in message:
            return jsonify({"response": response})

    return jsonify({"response": CHATBOT_RESPONSES["default"]})


if __name__ == "__main__":
    app.run(debug=True, port=5000)