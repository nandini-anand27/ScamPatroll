
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from difflib import SequenceMatcher
from datetime import datetime, timezone
import ipaddress
import re
import requests

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024

# Brands and their official domains to check for lookalikes
BRANDS = {
    "google.com": ["google"],
    "amazon.com": ["amazon"],
    "paypal.com": ["paypal"],
    "microsoft.com": ["microsoft"],
    "apple.com": ["apple"],
    "instagram.com": ["instagram"],
    "facebook.com": ["facebook"],
    "netflix.com": ["netflix"],
    "whatsapp.com": ["whatsapp"],
    "github.com": ["github"],
    "flipkart.com": ["flipkart"],
    "myntra.com": ["myntra"],
}


SCAM_PATTERNS = [
    # 1. Urgency, pressure and threats
    (
        r"\b(urgent|urgently|immediately|act now|last chance|final warning|"
        r"final notice|within 24 hours|within 10 minutes|time is running out|"
        r"limited time|respond immediately|take action now|"
        r"failure to respond|account will be closed|permanent closure|"
        r"service termination|legal action|penalty notice|critical alert|"
        r"emergency action required|avoid suspension|avoid deactivation|"
        r"last reminder|deadline today|expire today|expires shortly)\b",
        "Uses urgency or pressure-based language.", 15
    ),

    # 2. Banking, account and KYC impersonation
    (
        r"\b(account blocked|account suspended|account frozen|account locked|"
        r"account restricted|account compromised|account deactivated|"
        r"account disabled|account terminated|account will be closed|"
        r"verify your account|verify your identity|KYC expired|"
        r"KYC update|KYC pending|complete KYC|update KYC|"
        r"re.?KYC|bank account verification|unauthorized login|"
        r"unusual activity|suspicious login|security alert|"
        r"account access denied|update your details|reactivate account|"
        r"bank account blocked|PAN update required|Aadhaar verification)\b",
        "Claims there is a problem with an account or identity verification.", 20
    ),

    # 3. OTP, password and credential theft
    (
        r"\b(OTP|one.?time password|verification code|security code|"
        r"authentication code|login code|share your OTP|send your OTP|"
        r"tell me your OTP|enter your OTP|confirm your OTP|"
        r"UPI PIN|ATM PIN|card PIN|CVV|CVC|card security code|"
        r"net banking password|banking credentials|login credentials|"
        r"password reset|re.?enter password|confirm your password|"
        r"two.?factor authentication|recovery code|backup code|"
        r"screen.?sharing code|remote access code)\b",
        "Mentions sensitive authentication or banking information.", 20
    ),

    # 4. Payments, money transfers and fake fees
    (
        r"\b(send money|transfer money|send funds|wire transfer|"
        r"bank transfer|payment required|pay now|pay immediately|"
        r"processing fee|registration fee|advance fee|advance payment|"
        r"security deposit|release fee|clearance fee|withdrawal fee|"
        r"refund fee|claim fee|activation fee|verification fee|"
        r"unlocking fee|customs fee|service charge|transaction fee|"
        r"pay to receive|pay to unlock|deposit money|urgent payment|"
        r"outstanding balance|overdue payment|payment overdue|"
        r"pending payment|money transfer pending|wire funds|"
        r"gift card payment|payment confirmation required)\b",
        "Requests a payment, transfer, deposit or fee.", 20
    ),

    # 5. UPI, QR codes and payment-app tricks
    (
        r"\b(UPI collect request|collect request|approve payment|"
        r"approve collect|scan QR code|scan this QR|receive money through UPI|"
        r"enter UPI PIN to receive|UPI refund|UPI reward|"
        r"payment link|payment approval|request money|"
        r"accept payment request|UPI verification|"
        r"refund processing through UPI|payment reversed|"
        r"Google Pay reward|PhonePe reward|Paytm cashback)\b",
        "Mentions UPI or payment-app activity that should be verified.", 20
    ),

    # 6. Prizes, lotteries and giveaways
    (
        r"\b(you have won|you won|winner notification|lucky winner|"
        r"lucky draw winner|claim your prize|claim your reward|"
        r"free gift|free iPhone|free smartphone|cash prize|"
        r"lottery winner|lottery prize|jackpot winner|reward unlocked|"
        r"exclusive reward|prize awaiting collection|unclaimed prize|"
        r"congratulations winner|selected for a prize|"
        r"you are the lucky winner|guaranteed winnings|"
        r"redeem your reward|giveaway winner|claim before expiry)\b",
        "Contains an unexpected prize, lottery or giveaway claim.", 15
    ),

    # 7. Job, internship and work-from-home scams
    (
        r"\b(guaranteed job|job offer fee|pay for interview|"
        r"registration fee for job|work from home earnings|"
        r"earn daily from home|easy money online|no experience high salary|"
        r"instant job offer|job confirmation fee|interview fee|"
        r"training fee for job|security deposit for job|"
        r"recruitment fee|placement fee|task completion earnings|"
        r"like and subscribe to earn|prepaid task|"
        r"recharge to unlock tasks|telegram task job|"
        r"WhatsApp task job|earn money by rating|"
        r"pay to get hired|guaranteed internship)\b",
        "Contains wording associated with suspicious job or task offers.", 20
    ),

    # 8. Digital-arrest and authority impersonation
    (
        r"\b(digital arrest|virtual arrest|police warrant|arrest warrant|"
        r"CBI officer|customs seizure|police case against you|"
        r"you will be arrested|pay to avoid arrest|"
        r"pay or you will be arrested|money laundering case|"
        r"your Aadhaar is linked to crime|your SIM is involved in crime|"
        r"parcel contains illegal items|fake police officer|"
        r"investigation account freeze|secret investigation|"
        r"do not tell anyone|stay on video call with police|"
        r"government officer demands payment|court fine payment link)\b",
        "Contains threats or possible authority impersonation.", 30
    ),

    # 9. Delivery, courier and parcel scams
    (
        r"\b(parcel held|package held|delivery failed|"
        r"delivery address incomplete|confirm delivery address|"
        r"update shipping address|customs clearance fee|"
        r"parcel contains illegal items|courier fee pending|"
        r"redelivery fee|package awaiting collection|"
        r"shipment on hold|delivery charge pending|"
        r"pay customs duty|track your parcel urgently|"
        r"delivery attempt failed|release your parcel)\b",
        "Contains a delivery or parcel claim that may require verification.", 15
    ),

    # 10. Investment, stock and cryptocurrency scams
    (
        r"\b(guaranteed profit|risk.?free investment|double your money|"
        r"triple your money|daily guaranteed returns|"
        r"assured returns|fixed high returns|insider trading tip|"
        r"exclusive trading signals|crypto investment opportunity|"
        r"double your bitcoin|crypto giveaway|free cryptocurrency|"
        r"pump and dump|investment recovery fee|"
        r"recover trading losses|guaranteed stock tips|"
        r"secret investment strategy|limited investment slots|"
        r"instant trading profits|withdrawal tax before release|"
        r"pay tax to withdraw profits)\b",
        "Contains suspicious investment or cryptocurrency promises.", 20
    ),

    # 11. Loan, credit and debt scams
    (
        r"\b(guaranteed loan approval|instant loan approval|"
        r"loan without documents|loan processing fee|"
        r"advance loan fee|pay before loan disbursal|"
        r"pre.?approved loan|loan release charge|"
        r"credit score improvement fee|loan insurance fee|"
        r"debt settlement fee|instant credit limit|"
        r"loan account blocked|pay to release loan|"
        r"guaranteed credit card approval|debt collection threat)\b",
        "Contains suspicious loan, credit or debt-related wording.", 20
    ),

    # 12. Refunds, cashback and fake customer support
    (
        r"\b(refund approved click here|claim your refund|"
        r"refund pending|cashback pending|cashback expired|"
        r"refund verification|refund processing fee|"
        r"customer support number|call this support number|"
        r"helpline verification|remote support required|"
        r"install support app|share your screen for refund|"
        r"refund requires UPI PIN|refund requires OTP|"
        r"claim compensation now|payment reversal verification)\b",
        "Contains a refund, cashback or support request requiring verification.", 20
    ),

    # 13. Romance, friendship and emotional manipulation
    (
        r"\b(send money for emergency|help me urgently with money|"
        r"send money for flight ticket|customs fee for gift|"
        r"pay to release your gift|investment opportunity for couples|"
        r"gift stuck in customs|urgent financial help from online friend|"
        r"send gift card code|online friend needs money urgently)\b",
        "Contains a financial request that may involve emotional manipulation.", 15
    ),

    # 14. Phishing and suspicious link instructions
    (
        r"\b(click here|click the link|open this link|click this link|"
        r"tap here|visit this website|click below|login now|"
        r"download now|continue here|verify now|register here|"
        r"activate your account|unlock your account|"
        r"complete verification|confirm your identity|"
        r"secure your account|view your refund|follow this link|"
        r"update your payment details|sign in immediately)\b",
        "Encourages you to follow a link or take an online action.", 10
    ),

    # 15. Sensitive financial and identity information
    (
        r"\b(bank details|bank account number|credit card details|"
        r"debit card details|card expiry date|bank login details|"
        r"financial information|IFSC code|PAN number|Aadhaar number|"
        r"identity document|identity proof|passport details|"
        r"tax identification number|bank statement|salary details|"
        r"wallet PIN|net banking credentials|payment credentials)\b",
        "Mentions sensitive financial or identity information.", 20
    ),

    # 16. Tech support and malware installation
    (
        r"\b(your device is infected|virus detected call now|"
        r"install this APK|install unknown application|"
        r"disable antivirus|turn off Play Protect|"
        r"install remote access app|download AnyDesk|"
        r"download remote support|grant accessibility permission|"
        r"allow screen sharing|device security compromised|"
        r"call Microsoft support immediately|computer locked by police|"
        r"install this certificate|unknown sources installation)\b",
        "Contains a possible tech-support or suspicious installation request.", 20
    ),

    # 17. SIM, mobile and telecom scams
    (
        r"\b(SIM will be blocked|SIM card suspended|"
        r"mobile number deactivated|KYC for SIM|"
        r"SIM verification pending|update SIM KYC|"
        r"mobile connection terminated|telecom police complaint|"
        r"SIM linked to criminal activity|"
        r"reactivate mobile number|port your number urgently)\b",
        "Contains a mobile or SIM verification threat.", 20
    ),

    # 18. Tax, government benefits and identity impersonation
    (
        r"\b(tax refund claim|income tax refund pending|"
        r"tax penalty payment|government subsidy approved|"
        r"free government benefit claim|benefit payment suspended|"
        r"update Aadhaar immediately|PAN card suspended|"
        r"tax department warrant|government grant processing fee|"
        r"pension verification fee|subsidy release fee|"
        r"benefit claim expires today)\b",
        "Contains a government, tax or benefit claim requiring verification.", 20
    ),

    # 19. Account recovery and social-media impersonation
    (
        r"\b(your account will be deleted|copyright violation notice|"
        r"blue tick verification fee|verified badge payment|"
        r"account recovery agent|recover hacked account fee|"
        r"send login code to recover account|"
        r"social media account suspended|copyright strike appeal fee|"
        r"pay to restore account|fake account complaint link)\b",
        "Contains a possible social-media impersonation or recovery scam.", 15
    ),

    # 20. Fake charities and emergencies
    (
        r"\b(donate immediately|emergency donation required|"
        r"charity registration fee|urgent medical donation|"
        r"relief fund processing fee|disaster relief payment link|"
        r"donation doubled|guaranteed charity match|"
        r"send donation to personal account)\b",
        "Contains a donation or emergency fundraising request to verify.", 15
    ),

    # 21. Suspicious business and marketplace transactions
    (
        r"\b(pay outside the platform|advance payment to seller|"
        r"buyer overpaid refund difference|"
        r"seller verification fee|release payment through QR|"
        r"courier agent payment link|pay to receive buyer funds|"
        r"account upgrade required to receive payment|"
        r"pay deposit before viewing property|"
        r"rental property booking fee urgently)\b",
        "Contains a marketplace or transaction request that needs verification.", 15
    ),

    # 22. Generic suspicious promises
    (
        r"\b(guaranteed earnings|easy money|instant income|"
        r"no risk high reward|secret method to earn|"
        r"unlimited income opportunity|exclusive money making scheme|"
        r"get rich quickly|free money transfer|"
        r"claim unclaimed funds|inheritance payment release fee)\b",
        "Contains unusually attractive financial promises.", 15
    ),
]

INDIAN_SCAM_PATTERNS = [
    # UPI, banking and payment fraud
    (
        r"\b(UPI PIN daalo refund ke liye|"
        r"refund lene ke liye UPI PIN|"
        r"QR code scan karke paise receive karo|"
        r"paise receive karne ke liye PIN|"
        r"collect request approve karo|"
        r"bank account freeze ho jayega|"
        r"account band ho jayega|"
        r"KYC update nahi kiya toh SIM band|"
        r"bank se bol raha hoon OTP batao|"
        r"OTP share karo|"
        r"UPI refund ke liye payment karo)\b",
        "Contains an Indian UPI or banking scam indicator.", 25
    ),

    # Digital arrest and police impersonation
    (
        r"\b(digital arrest|"
        r"CBI se bol raha hoon|"
        r"Delhi police case|"
        r"Mumbai police se bol raha hoon|"
        r"customs mein parcel pakda gaya|"
        r"Aadhaar money laundering case|"
        r"SIM illegal activity mein use hua|"
        r"video call par arrest|"
        r"police verification ke liye payment|"
        r"arrest se bachne ke liye paise do|"
        r"RBI account verification fee)\b",
        "Contains a possible Indian authority-impersonation or digital-arrest scam.", 30
    ),

    # Fake jobs, internships and task scams
    (
        r"\b(ghar baithe roz paise kamao|"
        r"like karo aur paise kamao|"
        r"rating do aur paise kamao|"
        r"Telegram task job|"
        r"WhatsApp task job|"
        r"prepaid task recharge|"
        r"task unlock karne ke liye recharge|"
        r"job ke liye registration fee|"
        r"interview se pehle payment|"
        r"work from home guaranteed income|"
        r"review likhkar paise kamao)\b",
        "Contains a possible fake job or task-scam phrase.", 20
    ),

    # Betting, gaming and gambling-related money traps
    (
        r"\b(snooker betting|"
        r"snooker prediction guaranteed|"
        r"snooker fixed match|"
        r"fixed match sure shot|"
        r"100 percent winning prediction|"
        r"teen patti guaranteed income|"
        r"matka sure number|"
        r"satta king fixed number|"
        r"betting account recharge|"
        r"withdrawal unlock fee|"
        r"winning amount release fee|"
        r"betting loss recovery fee|"
        r"guaranteed betting profit)\b",
        "Contains a possible betting-related money scam indicator.", 20
    ),

    # Fake loan, subsidy and government benefit claims
    (
        r"\b(instant loan without documents|"
        r"loan release karne ke liye fee|"
        r"PM scheme registration fee|"
        r"government subsidy release fee|"
        r"free laptop scheme processing fee|"
        r"scholarship release fee|"
        r"pension verification payment|"
        r"lottery subsidy claim fee|"
        r"loan approval guaranteed after payment)\b",
        "Contains a possible fake loan or government-benefit claim.", 20
    ),

    # Courier, customs and parcel scams
    (
        r"\b(parcel mein illegal item|"
        r"customs clearance ke liye payment|"
        r"courier release fee|"
        r"parcel release karne ke liye paise|"
        r"delivery ke liye extra charge|"
        r"parcel mein drugs mile|"
        r"courier police case|"
        r"shipment customs mein roka gaya)\b",
        "Contains a possible courier or customs scam indicator.", 20
    ),

    # Investment, trading and crypto scams
    (
        r"\b(daily profit guaranteed|"
        r"double paisa in 7 days|"
        r"paise double karne ki scheme|"
        r"Telegram stock tips guaranteed|"
        r"VIP trading group guaranteed profit|"
        r"crypto withdrawal tax pehle do|"
        r"investment recovery fee|"
        r"loss recover karne ke liye deposit|"
        r"fixed return investment scheme)\b",
        "Contains a possible investment or trading scam indicator.", 20
    ),

    # Fake customer support and remote-access scams
    (
        r"\b(customer care se bol raha hoon OTP do|"
        r"refund ke liye screen share karo|"
        r"AnyDesk install karo refund ke liye|"
        r"remote access app install karo|"
        r"Play Protect band karo|"
        r"support ke liye APK install karo|"
        r"electricity connection aaj kat jayega|"
        r"bijli bill pending connection cut)\b",
        "Contains a possible fake support or remote-access scam indicator.", 20
    ),

    # Common Hinglish urgency and money-pressure phrases
    (
        r"\b(abhi payment karo|"
        r"turant paise bhejo|"
        r"warna account band|"
        r"aaj hi claim karo|"
        r"last chance offer|"
        r"pehle fee jama karo|"
        r"paise milne se pehle tax do|"
        r"secret code batao|"
        r"OTP kisi ko mat batana but mujhe batao)\b",
        "Contains urgent Hinglish wording that may indicate a scam.", 15
    ),
]



URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+|"""
    r"""\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b"""
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly"
}


def extract_urls(text):
    """Extract URLs without opening or visiting them."""
    results = []

    for raw in URL_PATTERN.findall(text):
        raw = raw.rstrip(".,!?;:)]}")

        candidate = raw if "://" in raw else "https://" + raw

        try:
            parsed = urlparse(candidate)
            host = parsed.hostname

            if not host:
                continue

            host = host.rstrip(".").lower()
            host = host.encode("idna").decode("ascii")

            results.append({
                "raw": raw,
                "host": host,
                "scheme": parsed.scheme.lower(),
                "parsed": parsed,
            })
        except (ValueError, UnicodeError):
            continue

    return list({item["host"]: item for item in results}.values())


def get_base_domain(host):
    """
    Approximate the registered domain.
    This is not a full public-suffix-list implementation.
    """
    parts = host.split(".")

    if len(parts) >= 3 and parts[-2] in {
        "co", "com", "net", "org", "gov", "ac"
    }:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_lookalikes(host):
    warnings = []

    # Exact official domains and their subdomains
    if any(
        host == official or host.endswith("." + official)
        for official in BRANDS
    ):
        return warnings

    substitutions = str.maketrans({
        "0": "o", "1": "l", "3": "e", "5": "s", "8": "b"
    })

    labels = host.split(".")[:-1]

    for official, brand_names in BRANDS.items():
        for label in labels:
            normalized = label.translate(substitutions)

            for brand in brand_names:
                similarity = SequenceMatcher(
                    None, normalized, brand
                ).ratio()

                if (
                    normalized == brand
                    or (
                        len(brand) >= 4
                        and len(normalized) >= 4
                        and similarity >= 0.80
                        and normalized != brand
                    )
                ):
                    warnings.append(
                        f"Possible brand impersonation: {host} resembles "
                        f"{official}. This is a warning, not proof of fraud."
                    )
                    return warnings

    return warnings


def check_url_security(url_info):
    warnings = []
    host = url_info["host"]
    raw = url_info["raw"]
    parsed = url_info["parsed"]

    try:
        ipaddress.ip_address(host.strip("[]"))
        warnings.append(
            f"IP-address URL detected: {host}. Verify its source carefully."
        )
    except ValueError:
        pass

    
    if parsed.scheme.lower() == "http":
        warnings.append({
            "warning": "Unsecured HTTP connection",
        "points": 25
    })

    if len(host.split(".")) >= 5:
        warnings.append(
            f"Many subdomain levels detected in {host}. Check the actual "
            "registered domain before trusting it."
        )

    if host in SHORTENERS:
        warnings.append(
            f"URL shortener detected: {host}. The final destination is hidden."
        )

    if "@" in raw:
        warnings.append(
            "URL contains an @ symbol, which may obscure its destination."
        )

    if len(raw) > 180:
        warnings.append(
            f"Unusually long URL detected: {host}. Inspect it carefully."
        )

    if any(label.startswith("xn--") for label in host.split(".")):
        warnings.append(
            f"Punycode domain detected: {host}. Check for lookalike characters."
        )

    return warnings


def check_domain_age(host):
    """
    Ask a public RDAP gateway for registration information.
    Returns None when unavailable; it does not visit the website itself.
    """
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    domain = get_base_domain(host)

    try:
        response = requests.get(
            "https://rdap.org/domain/" + domain,
            headers={"Accept": "application/rdap+json"},
            timeout=3
        )

        if response.status_code != 200:
            return None

        data = response.json()
        dates = []

        for event in data.get("events", []):
            if event.get("eventAction", "").lower() in {
                "registration", "registered"
            }:
                try:
                    date = datetime.fromisoformat(
                        event["eventDate"].replace("Z", "+00:00")
                    )
                    dates.append(date)
                except (ValueError, KeyError):
                    continue

        if not dates:
            return None

        registered = min(dates)
        age_days = (
            datetime.now(timezone.utc) - registered
        ).days

        if age_days < 0:
            return None

        return {
            "domain": domain,
            "registered": registered.date().isoformat(),
            "age_days": age_days
        }

    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None


def analyze_message(message):
    text = message.lower()
    flags = []
    score = 0

    def add_flag(warning, points):
        nonlocal score
        if warning not in flags:
            flags.append(warning)
            score += points

    # Message pattern detection
    for pattern, warning, points in SCAM_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            add_flag(warning, points)

    urls = extract_urls(message)

    if urls:
        add_flag(
            "Contains a URL. Check its destination carefully.", 10
        )

    domain_details = []

    for item in urls:
        host = item["host"]

        for warning in check_lookalikes(host):
            add_flag(warning, 35)

        
        for warning in check_url_security(item):
            if isinstance(warning, dict):
                add_flag(warning["warning"], warning["points"])
            else:
                add_flag(warning, 10)


        info = check_domain_age(host)

        if info:
            domain_details.append({
                "domain": info["domain"],
                "status": "Registration data found",
                "registered": info["registered"],
                "age_days": info["age_days"]
            })

            if info["age_days"] < 30:
                add_flag(
                    f"{info['domain']} appears newly registered "
                    f"({info['age_days']} days old). This alone does not "
                    "prove it is malicious.", 15
                )
            elif info["age_days"] < 180:
                add_flag(
                    f"{info['domain']} appears less than six months old. "
                    "Treat unexpected requests cautiously.", 5
                )
        else:
            domain_details.append({
                "domain": get_base_domain(host),
                "status": "Registration date unavailable"
            })

    score = min(score, 100)

    if score >= 60:
        level = "high"
        verdict = "High Risk Detected"
    elif score >= 30:
        level = "medium"
        verdict = "Medium Risk Detected"
    else:
        level = "low"
        verdict = "Low Risk Detected"

    if not flags:
        flags.append("No configured warning signs were found.")

    advice = []

    if score >= 60:
        advice.append(
            "Do not click suspicious links, install unexpected files, pay, "
            "or share passwords, OTPs, PINs, or identity details."
        )
    elif score >= 30:
        advice.append(
            "Pause and independently verify the sender using an official "
            "app, website, or phone number."
        )
    else:
        advice.append(
            "Few configured warning signs were detected. This does not "
            "prove the message or website is safe."
        )

    joined = " ".join(flags).lower()

    if any(word in joined for word in [
        "digital arrest", "police", "warrant", "customs", "threats"
    ]):
        advice.append(
            "Do not pay someone threatening arrest over a call or message. "
            "End the contact and verify independently."
        )

    if any(word in joined for word in [
        "otp", "password", "financial", "payment", "money"
    ]):
        advice.append(
            "Never share an OTP, UPI PIN, password, or card security code."
        )

    if urls:
        advice.append(
            "Check the exact domain. HTTPS alone does not prove legitimacy."
        )

    advice.append(
        "In India, report cybercrime at https://www.cybercrime.gov.in/. "
        "For financial cyber fraud, call 1930 promptly."
    )

    return {
        "score": score,
        "level": level,
        "verdict": verdict,
        "flags": flags,
        "advice": " ".join(advice),
        "domain_details": domain_details,
        "disclaimer": (
            "This tool uses heuristic checks and public registration data "
            "when available. It cannot guarantee that a message or website "
            "is safe or malicious. Verify important requests independently."
        )
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

    return jsonify(analyze_message(message))


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "The submitted request is too large."}), 413


if __name__ == "__main__":
    app.run(debug=True)
