
from flask import Flask, render_template, request, jsonify, send_from_directory
from difflib import SequenceMatcher
import re, time

app = Flask(__name__)

BLOCK_THRESHOLD = 0.40
MEMORY_THRESHOLD = 0.94

memory = {}
stats = {"total":0, "allowed":0, "blocked":0, "clarify":0}

SIGNATURES = {
    "PROMPT_INJECTION": [
        "ignore previous instructions",
        "ignore all previous instructions",
        "override previous instructions",
        "override the system instructions",
    ],
    "JAILBREAK": [
        "bypass safety",
        "disable safety",
        "bypass guardrails",
        "developer mode",
        "jailbreak",
    ],
    "SYSTEM_PROMPT_EXTRACTION": [
        "reveal your system prompt",
        "show your system prompt",
        "reveal hidden instructions",
        "show hidden instructions",
    ],
}

def normalize(text):
    text = (text or "").lower().strip()
    table = str.maketrans({"@":"a","4":"a","3":"e","1":"i","0":"o","$":"s"})
    text = text.translate(table)
    text = re.sub(r"[._\-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    for spaced, joined in {
        "h a c k":"hack",
        "b y p a s s":"bypass",
        "k i l l":"kill",
        "b o m b":"bomb",
        "p a s s w o r d":"password",
        "a c c o u n t":"account",
        "l o g i n":"login",
        "a c c e s s":"access",
    }.items():
        text = text.replace(spaced, joined)
    return text.strip()

def safe_context(text):
    if re.search(r"\b(kill|terminate)\s+(a\s+)?(linux\s+)?process\b", text):
        return True
    if re.search(r"\b(prescribed|prescription|doctor|pharmacist|medicine|medication)\b", text):
        return True
    if re.search(r"\b(protect|secure|prevent|defend|mitigate|detect|safety)\b", text) and \
       re.search(r"\b(account|password|hack|hacking|cyber|website|system|network)\b", text):
        return True
    if re.search(r"\b(explain|definition|what is|what are|assignment|research|study|awareness|history|prevention)\b", text):
        return True
    return False

def signature_detection(text):
    for category, phrases in SIGNATURES.items():
        for phrase in phrases:
            if phrase in text:
                return category, 0.99
    return None, 0.0

def heuristic_detection(text):
    safe = safe_context(text)

    if re.search(r"\b(kill myself|end my life|commit suicide|hurt myself|cut myself|die by suicide)\b", text):
        return "SELF_HARM", 0.99

    if not safe:
        if re.search(
            r"\b(kill|murder|stab|shoot|strangle|poison|assassinate|hurt|harm|attack)\b.{0,100}"
            r"\b(girl|woman|women|boy|man|person|someone|somebody|child|people|victim)\b",
            text
        ):
            return "VIOLENCE_HARMFUL", 0.99

        if re.search(
            r"\b(hack|crack|phish|breach|take over|break into|compromise|bypass)\b.{0,120}"
            r"\b(account|password|login|email|instagram|facebook|wifi|server|system|database|website|phone)\b",
            text
        ):
            return "CYBER_ABUSE", 0.98

        if re.search(
            r"\b(take|consume|inject|snort|smoke|use|buy|sell|prepare)\b.{0,90}"
            r"\b(cocaine|heroin|meth|methamphetamine|fentanyl|mdma|illegal drugs?|narcotics?)\b",
            text
        ):
            return "DRUGS", 0.98

        if re.search(
            r"\b(make|build|construct|assemble|detonate|use)\b.{0,100}"
            r"\b(bomb|explosive|grenade|weapon|detonator|ied)\b",
            text
        ):
            return "WEAPONS", 0.99

        if re.search(r"\b(scam|fraud|deceive|trick|impersonate)\b.{0,100}\b(money|payment|victim|customer|person|bank|financial)\b", text):
            return "FRAUD", 0.97

        if re.search(r"\b(track|stalk|monitor|watch|collect private|obtain private)\b.{0,120}\b(person|someone|individual|user|movements|information|details)\b", text) and \
           re.search(r"\b(secret|without permission|without them knowing|quietly|private)\b", text):
            return "PRIVACY_ABUSE", 0.97

    conceal = bool(re.search(
        r"\b(without being noticed|quietly|without the owner knowing|without permission|without leaving|"
        r"without anyone finding out|keep it secret|do not want to explain|don't want to explain|"
        r"rather not explain|without raising attention)\b", text
    ))
    suspicious_goal = bool(re.search(
        r"\b(get around|bypass|gain access|unauthorized access|take control|get inside|protected area|"
        r"private access|make .* disappear|make .* unusable|permanently solved|destructive solution)\b", text
    ))
    if not safe and conceal and suspicious_goal:
        return "AMBIGUOUS_TWISTED", 0.55

    return None, 0.0

def memory_detection(text):
    best, best_type = 0.0, None
    for stored, info in memory.items():
        score = SequenceMatcher(None, text, stored).ratio()
        if score > best:
            best = score
            best_type = info["attack"]
    return best_type, best

def safe_answer(prompt):
    text = normalize(prompt)
    if "machine learning" in text:
        return "Machine learning is a branch of AI that enables computers to learn patterns from data and make predictions or decisions."
    if "artificial intelligence" in text or text in {"what is ai","what is ai?"}:
        return "Artificial Intelligence is the field of building computer systems that can perform tasks such as learning, reasoning and decision-making."
    if "prompt injection" in text and ("what is" in text or "explain" in text):
        return "Prompt injection is an attack where malicious instructions are inserted into input to manipulate the intended behavior of an AI application."
    if "kill a process" in text:
        return "In Linux, find the process ID using ps or pgrep, then use `kill PID` to request normal termination."
    if re.search(r"\b(protect|secure|prevent)\b", text) and re.search(r"\b(account|hack|password)\b", text):
        return "Use a strong unique password, enable multi-factor authentication, avoid suspicious links, keep software updated and review login activity."
    return "This prompt passed the LLM Guard security gateway and was forwarded to the protected response layer."

def fallback(attack):
    messages = {
        "CYBER_ABUSE":"Request blocked. I can help with defensive cybersecurity instead.",
        "VIOLENCE_HARMFUL":"Request blocked because harmful intent was detected. I can help with safety, prevention or de-escalation instead.",
        "DRUGS":"Request blocked. I can provide health, awareness or prevention information instead.",
        "WEAPONS":"Request blocked. I can provide general safety information instead.",
        "PROMPT_INJECTION":"Request blocked because the input attempts to override protected instructions.",
        "JAILBREAK":"Request blocked because the input attempts to bypass safety controls.",
        "SYSTEM_PROMPT_EXTRACTION":"Protected system instructions cannot be revealed.",
        "FRAUD":"Request blocked because it may facilitate fraud or deception.",
        "PRIVACY_ABUSE":"Request blocked because it may violate another person's privacy.",
        "SELF_HARM":"I can’t help with self-harm instructions. Please seek immediate support from someone you trust or local emergency/crisis services if you may act on this.",
        "ADAPTIVE_MEMORY_MATCH":"A highly similar previously blocked threat was detected.",
    }
    return messages.get(attack, "This request was blocked by LLM Guard.")

def analyse_prompt(prompt):
    global stats
    raw = (prompt or "").strip()
    text = normalize(raw)
    stats["total"] += 1

    if not text:
        stats["clarify"] += 1
        return {
            "status":"NEEDS_CLARIFICATION","attack":"EMPTY_INPUT","risk":0.0,
            "signature":0.0,"heuristic":0.0,"ml":0.0,"memory":0.0,
            "response":"Please enter a prompt.","reason":"No input was provided.",
            "action":"REQUEST CLARIFICATION","forwarding":"BLOCKED"
        }

    sig_type, sig = signature_detection(text)
    heur_type, heur = heuristic_detection(text)
    mem_type, mem = memory_detection(text)

    if sig >= .90:
        ml = .96
    elif heur >= .90:
        ml = .95
    elif mem >= MEMORY_THRESHOLD:
        ml = .94
    elif heur_type == "AMBIGUOUS_TWISTED":
        ml = .50
    else:
        ml = .02

    risk = sig*.30 + heur*.25 + ml*.45
    attack = heur_type or sig_type or "CLEAN"
    reason = "No malicious behaviour detected."

    if mem >= MEMORY_THRESHOLD:
        attack = "ADAPTIVE_MEMORY_MATCH"
        risk = max(risk, .96)
        reason = "A highly similar previously blocked threat was detected."
    elif heur_type == "AMBIGUOUS_TWISTED":
        risk = max(risk, .45)
        reason = "Potentially harmful intent was detected but the purpose is unclear. Clarification is required."
    elif heur_type:
        reason = f"{heur_type.replace('_',' ').title()} indicators were detected."
    elif sig_type:
        reason = "A high-confidence prompt attack signature was detected."

    if risk > BLOCK_THRESHOLD:
        status = "BLOCKED"
        stats["blocked"] += 1
        forwarding = "BLOCKED"
        if attack == "AMBIGUOUS_TWISTED":
            stats["clarify"] += 1
            action = "REQUEST CLARIFICATION"
            response = "The intent is unclear and potentially harmful. Please clearly state the safe, educational, defensive, medical or legitimate purpose."
        else:
            action = "SAFE FALLBACK"
            response = fallback(attack)
        old = memory.get(text, {"attack":attack,"hits":0,"first_seen":int(time.time())})
        old["attack"] = attack
        old["hits"] = int(old.get("hits",0)) + 1
        old["last_seen"] = int(time.time())
        memory[text] = old
    else:
        status = "ALLOWED"
        attack = "CLEAN"
        stats["allowed"] += 1
        forwarding = "ALLOWED"
        action = "PROTECTED RESPONSE"
        response = safe_answer(raw)
        reason = f"Final malicious risk {risk*100:.2f}% is within the configured 40% threshold."

    return {
        "status":status,"attack":attack,"risk":round(float(risk),4),
        "signature":round(float(sig),4),"heuristic":round(float(heur),4),
        "ml":round(float(ml),4),"memory":round(float(mem),4),
        "response":response,"reason":reason,"action":action,"forwarding":forwarding
    }

def memory_items():
    return [{"prompt":p,"attack":i["attack"],"hits":i.get("hits",1)} for p,i in list(memory.items())[-20:][::-1]]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/manifest.json")
def manifest():
    return send_from_directory("static", "manifest.json", mimetype="application/manifest+json")

@app.route("/service-worker.js")
def sw():
    r = send_from_directory("static", "service-worker.js", mimetype="application/javascript")
    r.headers["Service-Worker-Allowed"] = "/"
    return r

@app.route("/api/analyse", methods=["POST"])
def api_analyse():
    data = request.get_json(silent=True) or {}
    result = analyse_prompt(data.get("prompt",""))
    result["stats"] = stats
    result["memory_items"] = memory_items()
    return jsonify(result)

@app.route("/api/status")
def api_status():
    return jsonify({"stats":stats,"memory_items":memory_items()})

@app.route("/health")
def health():
    return {"status":"ok"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
