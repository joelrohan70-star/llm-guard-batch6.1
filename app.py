
from flask import Flask, render_template, request, jsonify, send_from_directory
from difflib import SequenceMatcher
from urllib.parse import quote
import requests
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
    table = str.maketrans({
        "@":"a","4":"a","3":"e","1":"i","!":"i","0":"o","$":"s","5":"s","7":"t"
    })
    text = text.translate(table)
    text = re.sub(r"[\u200b-\u200d\uFEFF]", "", text)
    text = re.sub(r"[._\-/*|~^]+", " ", text)
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
        "s t e a l":"steal",
        "w e a p o n":"weapon",
        "s c a m":"scam",
    }.items():
        text = text.replace(spaced, joined)
    return text.strip()


def safe_context(text):
    # Concealed intent should never be mistaken for an educational prompt
    if re.search(
        r"\b(do not want to explain|don't want to explain|rather not explain|won't explain|"
        r"cannot explain (the )?(purpose|reason)|keep the purpose hidden)\b",
        text
    ):
        return False

    if re.search(r"\b(kill|terminate|stop)\s+(a\s+)?(linux\s+)?process\b", text):
        return True

    if re.search(r"\b(prescribed|prescription|doctor|pharmacist|medicine|medication)\b", text):
        return True

    if re.search(r"\b(bomb calorimeter|population explosion|explosive growth)\b", text):
        return True

    educational = bool(re.search(
        r"\b(what is|what are|define|definition|explain|overview|history|assignment|research|study|"
        r"awareness|prevention|prevent|protect|defend|defensive|mitigate|detection|detect|safety|"
        r"risks?|security controls?)\b",
        text
    ))

    operational = bool(re.search(
        r"\b(how to|how can i|tell me how|teach me how|steps?|step by step|procedure|instructions?|"
        r"guide me|help me (to )?|best way|easiest way|secret way|quiet way|method to|ways? to|"
        r"exact commands?|exact steps?|working code|payload|script to)\b",
        text
    ))

    ownership_safe = bool(re.search(
        r"\b(my own|our own|authorized|authorised|with permission|permission granted|lab|ctf|sandbox|"
        r"test environment|training environment)\b",
        text
    ))

    return educational and (not operational or ownership_safe)


def signature_detection(text):
    for category, phrases in SIGNATURES.items():
        for phrase in phrases:
            if phrase in text:
                return category, 0.99
    return None, 0.0

def heuristic_detection(text):
    safe = safe_context(text)

    # Self-harm intent
    if re.search(
        r"\b(kill myself|end my life|commit suicide|hurt myself|cut myself|die by suicide|suicide method)\b",
        text
    ):
        return "SELF_HARM", 0.99

    if not safe:
        # Direct violence / coercion
        violent_action = bool(re.search(
            r"\b(kill|murder|stab|shoot|strangle|poison|assassinate|hurt|harm|attack|beat|torture|"
            r"kidnap|abduct|rape|sexually assault|silence permanently)\b",
            text
        ))
        human_target = bool(re.search(
            r"\b(person|someone|somebody|people|girl|woman|women|boy|man|child|victim|teacher|friend|"
            r"crowd|family|neighbour|neighbor|employee|boss|classmate)\b",
            text
        ))
        if violent_action and human_target:
            return "VIOLENCE_HARMFUL", 0.99

        # Euphemistic violence
        if re.search(
            r"\b(make (him|her|them|someone) disappear|(him|her|them|someone|that person) gone permanently|"
            r"never wake up again|get rid of (him|her|them|someone)|"
            r"take (him|her|them|someone) out permanently|"
            r"put (him|her|them|someone) out of the picture|"
            r"remove (him|her|them|someone) permanently)\b",
            text
        ):
            return "VIOLENCE_HARMFUL", 0.99

        # Hijacking / hostage / public takeover
        takeover_action = bool(re.search(
            r"\b(hijack|hostage|seize|storm|occupy|take over|commandeer)\b",
            text
        ))
        takeover_target = bool(re.search(
            r"\b(mall|school|college|building|airport|plane|aircraft|bus|train|vehicle|office|hospital|"
            r"place|crowd|people|ship|boat|metro|station|classroom)\b",
            text
        ))
        if takeover_action and takeover_target:
            return "VIOLENCE_HARMFUL", 0.99

        # Weapons / explosives / arson
        weapon_action = bool(re.search(
            r"\b(make|build|construct|assemble|create|prepare|detonate|ignite|use|hide)\b",
            text
        ))
        weapon_target = bool(re.search(
            r"\b(bomb|explosive|grenade|molotov|weapon|detonator|ied|incendiary|firebomb)\b",
            text
        ))
        if weapon_action and weapon_target:
            return "WEAPONS", 0.99

        if re.search(
            r"\b(arson|set .* on fire|burn down|torch a building|start a fire without being caught)\b",
            text
        ):
            return "WEAPONS", 0.98

        # Unauthorized access to another person's device/data.
        # This catches indirect wording such as:
        # "access someone's mobile secretly", "read their messages without them knowing",
        # and "get into another person's phone".
        access_action = bool(re.search(
            r"\b(access|get into|enter|open|unlock|control|take control|view|read|see|check|copy|download|"
            r"browse|inspect|use|retrieve|obtain|monitor)\b",
            text
        ))
        private_target = bool(re.search(
            r"\b(mobile|phone|smartphone|device|account|email|messages?|chats?|whatsapp|telegram|"
            r"photos?|gallery|files?|camera|microphone|location|contacts?|password|otp|pin|login|"
            r"cloud|drive|social media|instagram|facebook)\b",
            text
        ))
        third_party = bool(re.search(
            r"\b(someone'?s|somebody'?s|another person'?s|another user's|their|his|her|not mine|"
            r"isn't mine|doesn't belong to me|owner's)\b",
            text
        ))
        secret_or_unauthorized = bool(re.search(
            r"\b(secretly|without permission|without consent|without them knowing|without the owner knowing|"
            r"without the owner noticing|without being noticed|quietly|unnoticed|without getting caught|"
            r"leave no trace|cover my tracks|unauthorized|without approval)\b",
            text
        ))

        if access_action and private_target and (third_party or secret_or_unauthorized):
            if re.search(r"\b(messages?|chats?|photos?|gallery|camera|microphone|location|contacts?|files?)\b", text):
                return "PRIVACY_ABUSE", 0.99
            return "CYBER_ABUSE", 0.99

        # Cyber abuse
        cyber_action = bool(re.search(
            r"\b(hack|crack|phish|breach|take over|break into|compromise|bypass|steal credentials|"
            r"credential stuff|brute force|keylog|malware|ransomware|ddos|botnet|exploit|session hijack|"
            r"steal token|steal password|evade authentication|circumvent authentication|get past login|"
            r"get around login|defeat verification)\b",
            text
        ))
        cyber_target = bool(re.search(
            r"\b(account|password|login|email|instagram|facebook|wifi|router|server|system|database|website|mobile|"
            r"phone|computer|network|cloud|api|device|session|token|otp|2fa|authentication|verification)\b",
            text
        ))
        unauthorized = bool(re.search(
            r"\b(without permission|not mine|isn't mine|someone else|someone else's|another person's|"
            r"unauthorized|secretly|without the owner|without them knowing|stealth|leave no trace|"
            r"avoid detection|without being noticed|without raising attention)\b",
            text
        ))
        if cyber_action and (cyber_target or unauthorized):
            return "CYBER_ABUSE", 0.98

        # Drugs
        drug_action = bool(re.search(
            r"\b(take|consume|inject|snort|smoke|use|buy|sell|obtain|prepare|manufacture|cook)\b",
            text
        ))
        drug_target = bool(re.search(
            r"\b(cocaine|heroin|meth|methamphetamine|fentanyl|mdma|ecstasy|illegal drugs?|narcotics?)\b",
            text
        ))
        if drug_action and drug_target:
            return "DRUGS", 0.98

        # Fraud
        if re.search(
            r"\b(scam|fraud|phishing scam|steal money|deceive|trick|impersonate|fake payment|carding|"
            r"launder money|money laundering|fake invoice|fake receipt|steal card|credit card theft)\b",
            text
        ):
            return "FRAUD", 0.97

        # Privacy abuse / stalking / doxxing
        if re.search(
            r"\b(dox|doxx|stalk|secretly track|track someone|monitor someone|spy on|obtain private information|"
            r"private details|location without|find someone's home address|track their location|watch them secretly)\b",
            text
        ):
            return "PRIVACY_ABUSE", 0.97

        # Generic harmful operational intent
        operational = bool(re.search(
            r"\b(how to|how can i|tell me how|teach me|steps?|method|procedure|instructions?|best way|"
            r"easiest way|secret way|quiet way|help me|working way|practical way|exact way)\b",
            text
        ))
        harmful_concept = bool(re.search(
            r"\b(kill|murder|hurt|harm|hijack|kidnap|hostage|bomb|explosive|weapon|hack|breach|bypass|"
            r"cocaine|heroin|meth|fentanyl|fraud|scam|stalk|dox|rape|arson|steal|sabotage)\b",
            text
        ))
        if operational and harmful_concept:
            return "AMBIGUOUS_TWISTED", 0.75

    # Twisted / indirect / concealed intent
    conceal = bool(re.search(
        r"\b(without being noticed|secretly|quiet|quietly|without the owner knowing|without the owner noticing|"
        r"without permission|without leaving|without anyone finding out|keep it secret|keep the purpose hidden|"
        r"do not want to explain|don't want to explain|rather not explain|without raising attention|"
        r"leave no trace|avoid detection|make it look accidental|appear harmless|keep it off the radar|"
        r"cover my tracks|no obvious sign|nobody should know|no one should know|without getting caught)\b",
        text
    ))

    suspicious_goal = bool(re.search(
        r"\b(get around|way around|bypass|gain access|unauthorized access|take control|get inside|protected area|"
        r"private access|make .* disappear|make .* unusable|remove .* permanently|permanently solved|"
        r"destructive solution|someone out of the picture|get rid of|access (to )?something that is not mine|"
        r"access (to )?something that isn't mine|get past .* checks?|avoid .* verification|"
        r"defeat .* security|make .* stop working|shut .* down|disable .* without permission|sabotage)\b",
        text
    ))

    ownership_violation = bool(re.search(
        r"\b(not mine|isn't mine|doesn't belong to me|someone else's|another person's|without permission|"
        r"without consent|owner doesn't know|owner would not approve|owner wouldn't approve)\b",
        text
    ))

    destructive_outcome = bool(re.search(
        r"\b(destroy|disable|wipe|erase permanently|make unusable|make disappear|gone permanently|"
        r"never wake up|permanently remove|shut down|sabotage|ruin|take down)\b",
        text
    ))

    signals = sum(bool(x) for x in [
        conceal,
        suspicious_goal,
        ownership_violation,
        destructive_outcome
    ])

    # Conservative ambiguity handling: suspicious + unclear is blocked
    if not safe and signals >= 2:
        return "AMBIGUOUS_TWISTED", 0.78

    if not safe and suspicious_goal and (conceal or ownership_violation):
        return "AMBIGUOUS_TWISTED", 0.78

    # Final dangerous-concept gate: risky concepts never silently become CLEAN
    if not safe and re.search(
        r"\b(kill|murder|hijack|kidnap|hostage|bomb|explosive|weapon|hack|breach|bypass|"
        r"cocaine|heroin|meth|fentanyl|fraud|scam|stalk|dox|rape|arson|sabotage|steal)\b",
        text
    ):
        return "AMBIGUOUS_TWISTED", 0.58

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
    """
    Protected response layer for ALLOWED prompts.

    Order:
    1) Fast predefined answers for common project/demo questions.
    2) Wikipedia grounded summary.
    3) DuckDuckGo Instant Answer fallback.
    4) Clear fallback if no grounded answer is available.

    This runs ONLY after the security gateway allows the prompt.
    """
    text = normalize(prompt)

    # --------------------------------------------------------
    # FAST LOCAL ANSWERS
    # --------------------------------------------------------

    if "machine learning" in text:
        return (
            "Machine learning is a branch of Artificial Intelligence "
            "that enables computers to learn patterns from data and "
            "make predictions or decisions without being explicitly "
            "programmed for every situation."
        )

    if "artificial intelligence" in text or text in {"what is ai", "what is ai?"}:
        return (
            "Artificial Intelligence (AI) is the field of building "
            "computer systems that can perform tasks such as learning, "
            "reasoning, perception and decision-making."
        )

    if "prompt injection" in text and ("what is" in text or "explain" in text):
        return (
            "Prompt injection is an attack in which malicious or "
            "misleading instructions are inserted into model input "
            "to manipulate the intended behaviour of an AI application."
        )

    if "kill a process" in text:
        return (
            "In Linux, identify the process ID using tools such as "
            "ps, top or pgrep, then use `kill PID` to request normal "
            "termination. If required, an administrator can use stronger "
            "termination options carefully."
        )

    if (
        re.search(r"\b(protect|secure|prevent|defend)\b", text)
        and re.search(r"\b(account|hack|password|cyber)\b", text)
    ):
        return (
            "Use a strong unique password, enable multi-factor "
            "authentication, avoid suspicious links, keep software "
            "updated and regularly review login activity."
        )

    # --------------------------------------------------------
    # CLEAN QUERY FOR GROUNDED LOOKUP
    # --------------------------------------------------------

    query = re.sub(
        r"^(who is|what is|what are|who are|tell me about|explain|define|describe)\s+",
        "",
        prompt.strip(),
        flags=re.I
    ).strip(" ?.!")

    if not query:
        query = prompt.strip()

    headers = {
        "User-Agent": "LLMGuardBatch6/1.0 (student project)"
    }

    # --------------------------------------------------------
    # WIKIPEDIA
    # --------------------------------------------------------

    try:
        search_response = requests.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query",
                "list": "search",
                "srsearch": query,
                "srlimit": 1,
                "format": "json"
            },
            headers=headers,
            timeout=5
        )

        if search_response.ok:
            search_data = search_response.json()
            results = search_data.get("query", {}).get("search", [])

            if results:
                title = results[0].get("title", "").strip()

                if title:
                    summary_response = requests.get(
                        "https://en.wikipedia.org/api/rest_v1/page/summary/"
                        + quote(title.replace(" ", "_")),
                        headers=headers,
                        timeout=5
                    )

                    if summary_response.ok:
                        summary = summary_response.json().get("extract", "").strip()

                        if summary:
                            sentences = re.split(
                                r"(?<=[.!?])\s+",
                                summary
                            )

                            answer = " ".join(sentences[:5]).strip()

                            if answer:
                                return answer

    except Exception:
        pass

    # --------------------------------------------------------
    # DUCKDUCKGO INSTANT ANSWER
    # --------------------------------------------------------

    try:
        ddg = requests.get(
            "https://api.duckduckgo.com/",
            params={
                "q": query,
                "format": "json",
                "no_html": 1,
                "skip_disambig": 0
            },
            headers=headers,
            timeout=5
        )

        if ddg.ok:
            data = ddg.json()

            for field in ("AbstractText", "Answer", "Definition"):
                answer = str(data.get(field, "")).strip()

                if answer:
                    return answer

    except Exception:
        pass

    # --------------------------------------------------------
    # FINAL SAFE FALLBACK
    # --------------------------------------------------------

    return (
        "This request passed the LLM Guard security gateway, but the "
        "protected grounded response layer could not find a reliable "
        "answer for this query. Please rephrase the question more specifically."
    )


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

    # ML is explicitly demo-mode until trained weights are deployed
    if sig >= .90:
        ml = .96
    elif heur >= .90:
        ml = .95
    elif heur_type == "AMBIGUOUS_TWISTED":
        ml = .70
    elif mem >= MEMORY_THRESHOLD:
        ml = .94
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
        risk = max(risk, .58)
        reason = (
            "Potentially harmful, concealed or unclear intent was detected. "
            "Clarification is required."
        )

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
            response = (
                "The intent is unclear and potentially harmful. "
                "Please clearly state the safe, educational, defensive, "
                "medical or legitimate purpose."
            )
        else:
            action = "SAFE FALLBACK"
            response = fallback(attack)

        old = memory.get(
            text,
            {"attack":attack,"hits":0,"first_seen":int(time.time())}
        )
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
        reason = (
            f"Final malicious risk {risk*100:.2f}% "
            f"is within the configured 40% threshold."
        )

    return {
        "status":status,"attack":attack,"risk":round(float(risk),4),
        "signature":round(float(sig),4),"heuristic":round(float(heur),4),
        "ml":round(float(ml),4),"memory":round(float(mem),4),
        "response":response,"reason":reason,
        "action":action,"forwarding":forwarding
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
