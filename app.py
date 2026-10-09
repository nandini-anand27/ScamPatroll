
from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)


def analyze_message(message):
    text = message.lower()

    flags = []
    score = 0

    patterns = [
        (
            r"\b(bank|otp|urgent|immediately|act now|within 24 hours|bank account blocked|final warning|account blocked|account suspended|will be deactivated within 24 hours|within 10 minutes|immediate action required|emergency|critical alert|verify now|respond immediately|avoid suspension|permanent closure|legal action|penalty notice|final notice|security alert|unauthorized access|unusual activity|account locked|service termination)\b",
            "Uses urgent or pressure-based language.",
            20
        ),
        (
            r"\b(verify your account|account suspended|account blocked|account restricted|account compromised|account deactivated|unusual activity|security alert|account verification|KYC expired|verify your account|account will be closed|unauthorized login|account access denied|update your details|immediate action required)\b",
            "Claims there is a problem with your account.",
            25
        ),
        (
            r"\b(winner|won a prize|claim your prize|free gift|you have won|congratulations winner|claim your prize|you are selected|free gift|cash prize|exclusive reward|lucky draw winner|claim your reward|you won a lottery|reward unlocked|prize awaiting collection|limited-time reward|processing fee required|claim before expiry|winner notification|free iPhone|guaranteed winnings|unclaimed prize|redeem your reward)\b",
            "Contains an unexpected prize or reward claim.",
            20
        ),
        (
            r"\b(password|otp|one-time password|pin|login credentials|verify your account|account verification|enter your OTP|share your OTP|security code|PIN|UPI PIN|CVV card number|banking details|confirm your identity|authentication code|password reset|login verification|account security|two-factor authentication|verify your identity|re-enter password|sensitive information|identity verification|banking credentials)\b",
            "Mentions sensitive login or verification details.",
            25
        ),
        (
            r"\b(send money|transfer money|pay a fee|payment required|send money transfer|funds|make a payment|pay now|urgent payment|processing fee|registration fee|advance payment|security deposit|transaction fee|transfer money|payment required|claim fee|release fee|refund fee|recharge your account|deposit money|wire transfer|bank transfer|UPI payment|scan QR code|pay to receive money|money pending payment confirmation|payment overdue|outstanding balance|pay immediately|send funds|payment verification|service charge|withdrawal fee|clearance fee.)\b",
            "Requests a payment or money transfer.",
            25
        ),
        (
            r"\b(click here|click the link|open this link|click here|click this link|tap here|visit this website|open the link|click below|verify now|login now|claim your reward|claim your prize|access your account|continue here|view details|learn more|download now|update your account|confirm your identity|verify your account|activate your account|unlock your reward|redeem now|register here|apply now|proceed immediately|take action now|follow this link|check your status|secure your account|view your refund|complete verification|click to avoid suspension.)\b",
            "Encourages you to click a link.",
            10
        ),
        (
            r"\b(bank details|credit card|debit card|bank account number|debit card|credit card|CVV card|PIN|UPI PIN|banking password|net banking credentials|IFSC code|account balance|transaction details|credit card details|debit card details|payment information|billing address|bank login details|financial information|OTP for banking|card expiry date|account number verification|payment credentials|wallet PIN|loan details|tax identification number|PAN number|Aadhaar number|bank statement|salary details|income information|investment account details.)\b",
            "Mentions sensitive financial information.",
            20
        ),
        (
            r"https?://\S+|www\.\S+",
            "Contains a URL. Check its destination carefully.",
            10
        ),
        (
            r"\b(bit\.ly|tinyurl\.com|t\.co|is\.gd)/\S*",
            "Contains a shortened URL.",
            20
        ),
        (
            r"\b(guaranteed profit|gift card|crypto investment)\b",
            "Contains wording commonly associated with scams.",
            20
        )
    ]

    for pattern, warning, points in patterns:
        if re.search(pattern, text) and warning not in flags:
            flags.append(warning)
            score += points

    score = min(score, 100)

    if score >= 60:
        level = "high"
        verdict = "High Risk Detected"
        advice = (
            "Do not click suspicious links or share sensitive details. "
            "Verify the message using official contact information."
        )

    elif score >= 30:
        level = "medium"
        verdict = "Medium Risk Detected"
        advice = (
            "Be cautious. Check the sender and independently verify "
            "the request before taking action."
        )

    else:
        level = "low"
        verdict = "Low Risk Detected"
        advice = (
            "Few configured warning signs were detected. This does not "
            "prove the message is safe. Verify unexpected requests."
        )

    if not flags:
        flags.append("No configured warning signs were found.")

    return {
        "score": score,
        "level": level,
        "verdict": verdict,
        "flags": flags,
        "advice": advice
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    message = data.get("text", "")

    if not isinstance(message, str) or not message.strip():
        return jsonify({
            "error": "Please paste a message or link first."
        }), 400

    if len(message) > 5000:
        return jsonify({
            "error": "Your message must be under 5000 characters."
        }), 400

    result = analyze_message(message)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)