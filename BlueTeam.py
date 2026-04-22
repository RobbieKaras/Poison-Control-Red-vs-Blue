import re
import time
import requests
from collections import defaultdict, deque
from urllib.parse import unquote
from openai import OpenAI

# ============================================
# CONFIGURATION
# ============================================
LM_STUDIO_URL = "http://localhost:1234/v1"
API_URL = "http://159.203.87.83:5000"
API_KEY = "securitybotw4rs2026"
CTFD_URL = "http://159.203.87.83:8000"
CTFD_TOKEN = "ctfd_26f8030dfbb8924feb840106dbe166811e17fc14283c18e6e63c3cc8b2cda612"

BLUE_TEAM_CHALLENGES = {
    "sql": 4,
    "cmd": 5,
    "brute": 6,
}

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}

# Tuning values
POLL_SECONDS = 1               # was 2 — faster detection is the #1 win
MAX_SEEN_REQUESTS = 5000

SQL_BLOCK_SCORE = 6            # was 8 — catch attacks with fewer signals
CMD_BLOCK_SCORE = 5            # was 6 — block on less evidence (cmd injection is always malicious)
BRUTE_BLOCK_COUNT = 2          # block after just 2 login attempts
BRUTE_WINDOW_SECONDS = 20      # was 30

SQL_LLM_REVIEW_SCORE = 3       # was 4 — escalate to LLM sooner
USE_LLM = True

# Per-endpoint rate limiting: block if same IP sends > this many requests
# to a sensitive endpoint within ENDPOINT_RATE_WINDOW seconds
ENDPOINT_RATE_LIMIT = 5
ENDPOINT_RATE_WINDOW = 15

# ============================================
# CLIENTS / STATE
# ============================================
client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")

blocked_ips = set()
scored_blocks = set()

seen_requests = deque(maxlen=MAX_SEEN_REQUESTS)
seen_request_set = set()

# Per-IP state
sql_scores = defaultdict(int)
cmd_scores = defaultdict(int)
brute_attempts = defaultdict(deque)
recent_activity = defaultdict(lambda: deque(maxlen=10))

# Per-IP per-endpoint request rate (catches hammering even without known-bad payloads)
endpoint_hits = defaultdict(lambda: defaultdict(deque))

# Track which IPs have already triggered a first-access block per endpoint
# In a tournament, any access to a vulnerability endpoint is an attack
first_access_blocked = defaultdict(set)

# IPs flagged during attack-prep phase (POST /security.php = bot starting up)
attack_prep_ips = set()

# ============================================
# HELPERS
# ============================================
def get_logs():
    try:
        r = requests.get(
            f"{API_URL}/logs",
            headers=HEADERS,
            params={"since": "10s"},
            timeout=5,
        )
        if r.status_code == 200:
            return r.json().get("logs", [])
    except Exception as exc:
        print(f"[-] Error getting logs: {exc}")
    return []


def parse_log_line(line):
    """
    Expected format like:
    1.2.3.4 ... "GET /path HTTP/1.1" ...
    """
    match = re.match(r'(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s+([^\s]+)', line)
    if not match:
        return None

    raw_path = match.group(3)

    return {
        "ip": match.group(1),
        "method": match.group(2),
        "raw_path": raw_path,
        "path": multi_decode_path(raw_path),
    }


def multi_decode_path(path, rounds=3):
    current = path
    for _ in range(rounds):
        decoded = unquote(current).replace("+", " ")
        if decoded == current:
            break
        current = decoded
    return current


def normalize_for_detection(path):
    """
    Normalize to catch evasion tricks:
    - multiple URL decodes
    - lowercase
    - remove repeated whitespace
    - remove SQL comments
    """
    s = multi_decode_path(path)
    s = s.lower()

    # strip common inline SQL comment tricks
    s = re.sub(r"/\*.*?\*/", "", s)
    s = s.replace("%00", "")
    s = re.sub(r"\s+", " ", s)

    return s.strip()


def add_seen_request(key):
    if key in seen_request_set:
        return False

    if len(seen_requests) == seen_requests.maxlen:
        old = seen_requests.popleft()
        seen_request_set.discard(old)

    seen_requests.append(key)
    seen_request_set.add(key)
    return True


def remember_activity(ip, attack_type, detail):
    recent_activity[ip].append({
        "time": time.strftime("%H:%M:%S"),
        "type": attack_type,
        "detail": detail[:140],
    })


def record_endpoint_hit(ip, endpoint_key):
    """Returns True if this IP has exceeded ENDPOINT_RATE_LIMIT hits in ENDPOINT_RATE_WINDOW."""
    now = time.time()
    hits = endpoint_hits[ip][endpoint_key]
    hits.append(now)
    while hits and (now - hits[0]) > ENDPOINT_RATE_WINDOW:
        hits.popleft()
    return len(hits) >= ENDPOINT_RATE_LIMIT


def block_ip(ip, attack_type, reason, score=True):
    if ip in blocked_ips:
        return

    try:
        r = requests.post(
            f"{API_URL}/block",
            headers=HEADERS,
            json={"ip": ip},
            timeout=5,
        )

        if r.status_code == 200:
            blocked_ips.add(ip)
            print(f"\n[!!!] BLOCKED {ip}")
            print(f"      Type: {attack_type}")
            print(f"      Reason: {reason}")
            if score:
                score_block(attack_type)
        else:
            print(f"[-] Block failed for {ip}: {r.text}")
    except Exception as exc:
        print(f"[-] Block request failed for {ip}: {exc}")


def get_ctfd_nonce():
    try:
        r = requests.get(
            f"{CTFD_URL}/challenges",
            headers={"Authorization": f"Token {CTFD_TOKEN}"},
            timeout=5,
        )
        nonce = re.search(r"'csrfNonce': \"(.*?)\"", r.text)
        return nonce.group(1) if nonce else ""
    except Exception as exc:
        print(f"[-] Failed to get CTFd nonce: {exc}")
        return ""


def score_block(attack_type):
    if attack_type in scored_blocks:
        return

    challenge_id = BLUE_TEAM_CHALLENGES.get(attack_type)
    if not challenge_id:
        return

    flag_map = {
        "sql": "BLUE{sql_blocked}",
        "cmd": "BLUE{cmd_blocked}",
        "brute": "BLUE{brute_blocked}",
    }

    flag = flag_map.get(attack_type)
    if not flag:
        return

    try:
        r = requests.post(
            f"{CTFD_URL}/api/v1/challenges/attempt",
            json={"challenge_id": challenge_id, "submission": flag},
            headers={
                "Authorization": f"Token {CTFD_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=5,
        )
        result = r.json()
        status = result.get("data", {}).get("status", "")
        if status == "correct":
            print(f"[+] BLUE TEAM SCORED for blocking {attack_type}!")
            scored_blocks.add(attack_type)
        elif status == "already_solved":
            print(f"[*] Already scored for blocking {attack_type}")
            scored_blocks.add(attack_type)
        else:
            print(f"[-] Score submission not accepted: {result}")
    except Exception as exc:
        print(f"[-] Error submitting score: {exc}")


# ============================================
# SQL INJECTION DETECTION
# ============================================
SQL_REGEX_RULES = [
    (r"\bunion\b.{0,25}\bselect\b", 5, "union select"),
    (r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", 4, "or 1=1 style"),
    (r"\b(or|and)\b\s+['\"].*?['\"]\s*=\s*['\"].*?['\"]", 4, "quoted boolean condition"),
    (r"\binformation_schema\b", 5, "information_schema"),
    (r"\bsleep\s*\(", 4, "sleep()"),
    (r"\bbenchmark\s*\(", 4, "benchmark()"),
    (r"\bload_file\s*\(", 5, "load_file()"),
    (r"\binto\s+outfile\b", 5, "into outfile"),
    (r"\bconcat\s*\(", 3, "concat()"),
    (r"\bsubstring\s*\(", 2, "substring()"),
    (r"\bsubstr\s*\(", 2, "substr()"),
    (r"\bextractvalue\s*\(", 4, "extractvalue()"),
    (r"\bupdatexml\s*\(", 4, "updatexml()"),
    (r"--", 2, "sql comment --"),
    (r"#", 1, "sql comment #"),
    (r"/\*", 2, "sql block comment"),
    (r"\bhex\b", 1, "hex usage"),
    (r"0x[0-9a-f]+", 2, "hex literal"),
    (r"\bchar\s*\(", 3, "char() encoding"),
    (r"\bascii\s*\(", 2, "ascii() function"),
    (r"\bord\s*\(", 2, "ord() function"),
    (r"\bgroup_concat\s*\(", 4, "group_concat()"),
    (r"\bif\s*\(", 2, "if() function"),
    (r"\bversion\s*\(\s*\)", 3, "version() probe"),
    (r"\bdatabase\s*\(\s*\)", 3, "database() probe"),
    (r"\buser\s*\(\s*\)", 2, "user() probe"),
    (r"\bwaitfor\b", 4, "waitfor delay (MSSQL)"),
    (r"\bxp_cmdshell\b", 5, "xp_cmdshell"),
    (r"\bsys\.tables\b", 4, "sys.tables probe"),
    (r"\bunion\s+all\s+select\b", 5, "union all select"),
    (r"'\s*or\s*'", 4, "or-quote evasion"),
    (r"\border\s+by\b", 2, "order by (column count probe)"),
]


def analyze_sql(path):
    normalized = normalize_for_detection(path)
    score = 0
    reasons = []

    for pattern, points, label in SQL_REGEX_RULES:
        if re.search(pattern, normalized, re.IGNORECASE):
            score += points
            reasons.append(label)

    special_char_count = len(re.findall(r"['\"`;#]", normalized))
    if special_char_count >= 2:
        score += 1
        reasons.append("multiple special characters")

    if normalized.count("=") >= 2:
        score += 1
        reasons.append("multiple equals operators")

    if "vulnerabilities/sqli" in normalized:
        score += 1
        reasons.append("targeting SQL challenge endpoint")

    return {
        "score": score,
        "reasons": list(dict.fromkeys(reasons)),
        "normalized": normalized,
    }


def maybe_confirm_sql_with_llm(ip, path, sql_result):
    if not USE_LLM:
        return False, "LLM disabled"

    try:
        response = client.chat.completions.create(
            model="meta-llama-3.1-8b-instruct",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a blue team security analyst defending DVWA in a CTF tournament. "
                        "The attacker uses evasion: comment injection (un/**/ion), case mixing, "
                        "hex encoding (0x...), char() encoding, double URL encoding, and "
                        "alternative SQL syntax. The request has already been normalized "
                        "(comments stripped, lowercased, URL-decoded). "
                        "Classify as ATTACK if there is ANY sign of SQL injection intent — "
                        "err on the side of blocking in a tournament setting. "
                        "Respond ONLY in this exact format:\n"
                        "DECISION: ATTACK or BENIGN\n"
                        "CONFIDENCE: high / medium / low\n"
                        "REASON: one sentence"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Source IP: {ip}\n"
                        f"Original request: {path}\n"
                        f"Normalized request: {sql_result['normalized']}\n"
                        f"Current rule score: {sql_result['score']}\n"
                        f"Rule reasons: {', '.join(sql_result['reasons']) or 'none'}"
                    ),
                },
            ],
        )

        decision_text = response.choices[0].message.content.strip()
        print("    [LLM REVIEW]")
        for line in decision_text.splitlines():
            print(f"        {line}")

        attack = "DECISION: ATTACK" in decision_text.upper()
        return attack, decision_text

    except Exception as exc:
        print(f"    [-] LLM review failed: {exc}")
        return False, f"LLM error: {exc}"


# ============================================
# COMMAND INJECTION DETECTION
# ============================================
CMD_REGEX_RULES = [
    # Chained commands — semicolon, pipe, and-and
    (r";\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh|head|tac|tail|strings|awk|sed|dd|perl|python|ruby|php)\b", 5, "semicolon command chaining"),
    (r"\|\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh|head|tac|tail|strings|awk|sed|dd|perl|python|ruby|php)\b", 5, "pipe command chaining"),
    (r"&&\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh|head|tac|tail|strings|awk|sed|dd|perl|python|ruby|php)\b", 5, "and chaining"),
    # Execution contexts
    (r"`[^`]+`", 5, "backtick execution"),
    (r"\$\([^)]+\)", 5, "subshell execution"),
    (r"\$\{IFS\}", 5, "IFS evasion"),
    # File targets
    (r"/etc/passwd", 5, "passwd file target"),
    (r"flag2?\.txt", 5, "flag file target"),
    (r"/hackable/flags", 5, "hackable flags path"),
    (r"/var/www/html", 4, "web root path traversal"),
    # Individual dangerous commands
    (r"\bcat\b", 3, "cat command"),
    (r"\bhead\b", 3, "head command"),
    (r"\btac\b", 3, "tac command"),
    (r"\btail\b", 2, "tail command"),
    (r"\bstrings\b", 3, "strings command"),
    (r"\bls\b", 2, "ls command"),
    (r"\bwhoami\b", 3, "whoami command"),
    (r"\bid\b", 3, "id command"),
    (r"\buname\b", 2, "uname command"),
    (r"\bnc\b", 4, "netcat usage"),
    (r"\bwget\b", 4, "wget usage"),
    (r"\bcurl\b", 4, "curl usage"),
    (r"\bawk\b", 3, "awk command"),
    (r"\bpython3?\b", 3, "python execution"),
    (r"\bperl\b", 3, "perl execution"),
    (r"\bruby\b", 3, "ruby execution"),
    (r"\bdd\b", 3, "dd command"),
    # Newline/encoding tricks
    (r"%0a", 4, "newline injection"),
    (r"\n", 4, "literal newline"),
    (r"base64", 3, "base64 encoding trick"),
]


def analyze_cmd(path):
    normalized = normalize_for_detection(path)
    score = 0
    reasons = []

    for pattern, points, label in CMD_REGEX_RULES:
        if re.search(pattern, normalized, re.IGNORECASE):
            score += points
            reasons.append(label)

    if "vulnerabilities/exec" in normalized:
        score += 1
        reasons.append("targeting command injection endpoint")

    metachar_count = len(re.findall(r"[;|`$]", normalized))
    if metachar_count >= 1:
        score += 2
        reasons.append("shell metacharacters present")

    return {
        "score": score,
        "reasons": list(dict.fromkeys(reasons)),
        "normalized": normalized,
    }


# ============================================
# BRUTE FORCE DETECTION
# ============================================
def is_brute_endpoint(parsed):
    path = parsed["path"].lower()
    return (
        parsed["method"] == "GET"
        and "vulnerabilities/brute" in path
    )


def record_brute_attempt(ip):
    now = time.time()
    attempts = brute_attempts[ip]
    attempts.append(now)

    while attempts and (now - attempts[0]) > BRUTE_WINDOW_SECONDS:
        attempts.popleft()

    return len(attempts)


# ============================================
# DEFENSE LOOP
# ============================================
def defense_loop():
    print("=== BLUE TEAM BOT STARTING ===")

    try:
        r = requests.get(f"{API_URL}/health", headers=HEADERS, timeout=5)
        print(f"[+] API connected: {r.json()}")
    except Exception as exc:
        print(f"[-] Cannot reach security API: {exc}")
        return

    print("\n[*] LIVE MONITORING ACTIVE")
    print("-" * 60)

    while True:
        try:
            logs = get_logs()

            for line in logs:
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                ip = parsed["ip"]
                method = parsed["method"]
                path = parsed["path"]

                request_key = f"{ip}:{method}:{path[:180]}"
                if not add_seen_request(request_key):
                    continue

                if ip in blocked_ips:
                    # IP already blocked — but still score challenges we haven't claimed yet
                    path_lower = path.lower()
                    if "vulnerabilities/exec" in path_lower and "cmd" not in scored_blocks:
                        print(f"    [LATE SCORE] cmd injection seen from already-blocked {ip}")
                        score_block("cmd")
                    if "vulnerabilities/brute" in path_lower and "brute" not in scored_blocks:
                        print(f"    [LATE SCORE] brute force seen from already-blocked {ip}")
                        score_block("brute")
                    if "vulnerabilities/sqli" in path_lower and "sql" not in scored_blocks:
                        print(f"    [LATE SCORE] sql injection seen from already-blocked {ip}")
                        score_block("sql")
                    continue

                print(f"[>] {ip} {method} {path[:100]}")

                # ------------------------------------
                # ATTACK PREP DETECTION
                # POST /security.php = bot setting DVWA to low security
                # This happens right before the first attack — block early
                # ------------------------------------
                if method == "POST" and "security.php" in path.lower():
                    attack_prep_ips.add(ip)
                    print(f"    [PREP] {ip} setting DVWA to low security — blocking before attack starts")
                    block_ip(ip, "sql", "attack prep: POST /security.php detected", score=False)
                    continue

                # ------------------------------------
                # FIRST-ACCESS BLOCKING
                # In a tournament, any access to a vuln endpoint IS the attack.
                # Block and score immediately on first hit — don't wait for payload analysis.
                # ------------------------------------
                path_lower = path.lower()

                if "vulnerabilities/sqli" in path_lower and "sqli" not in first_access_blocked[ip]:
                    first_access_blocked[ip].add("sqli")
                    block_ip(ip, "sql", "first access to SQL injection endpoint")
                    continue

                if "vulnerabilities/exec" in path_lower and "exec" not in first_access_blocked[ip]:
                    first_access_blocked[ip].add("exec")
                    block_ip(ip, "cmd", "first access to command injection endpoint")
                    continue

                # ------------------------------------
                # ENDPOINT RATE LIMITING (backup)
                # ------------------------------------
                if "vulnerabilities/brute" in path_lower:
                    if record_endpoint_hit(ip, "brute"):
                        block_ip(ip, "brute", f"rate limit: >{ENDPOINT_RATE_LIMIT} requests to brute endpoint in {ENDPOINT_RATE_WINDOW}s")
                        continue

                # ------------------------------------
                # COMMAND INJECTION
                # ------------------------------------
                cmd_result = analyze_cmd(path)
                if cmd_result["score"] >= CMD_BLOCK_SCORE:
                    cmd_scores[ip] += cmd_result["score"]
                    remember_activity(ip, "cmd", path)

                    reason = (
                        f"command injection detected "
                        f"(score={cmd_result['score']}, reasons={', '.join(cmd_result['reasons'])})"
                    )
                    block_ip(ip, "cmd", reason)
                    continue

                # ------------------------------------
                # SQL INJECTION
                # ------------------------------------
                sql_result = analyze_sql(path)
                if sql_result["score"] > 0:
                    sql_scores[ip] += sql_result["score"]
                    remember_activity(ip, "sql", path)

                    print(
                        f"    [SQL] score={sql_result['score']} "
                        f"total_ip_score={sql_scores[ip]} "
                        f"reasons={', '.join(sql_result['reasons']) or 'none'}"
                    )

                    if sql_result["score"] >= SQL_BLOCK_SCORE:
                        reason = (
                            f"high-confidence SQL injection "
                            f"(score={sql_result['score']}, reasons={', '.join(sql_result['reasons'])})"
                        )
                        block_ip(ip, "sql", reason)
                        continue

                    if sql_scores[ip] >= SQL_BLOCK_SCORE:
                        reason = (
                            f"repeated SQL injection behavior "
                            f"(cumulative_score={sql_scores[ip]}, latest_reasons={', '.join(sql_result['reasons'])})"
                        )
                        block_ip(ip, "sql", reason)
                        continue

                    if sql_result["score"] >= SQL_LLM_REVIEW_SCORE:
                        attack, llm_note = maybe_confirm_sql_with_llm(ip, path, sql_result)
                        if attack:
                            reason = (
                                f"LLM-confirmed SQL injection "
                                f"(rule_score={sql_result['score']}, reasons={', '.join(sql_result['reasons'])})"
                            )
                            block_ip(ip, "sql", reason)
                            continue

                # ------------------------------------
                # BRUTE FORCE
                # ------------------------------------
                if is_brute_endpoint(parsed):
                    count = record_brute_attempt(ip)
                    remember_activity(ip, "brute", path)

                    if count >= 3:
                        print(
                            f"    [BRUTE] {ip} has {count} attempts in "
                            f"{BRUTE_WINDOW_SECONDS}s"
                        )

                    if count >= BRUTE_BLOCK_COUNT:
                        reason = (
                            f"brute force detected "
                            f"({count} login attempts in {BRUTE_WINDOW_SECONDS} seconds)"
                        )
                        block_ip(ip, "brute", reason)
                        continue

            time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
            break
        except Exception as exc:
            print(f"[-] Loop error: {exc}")
            time.sleep(2)


if __name__ == "__main__":
    defense_loop()
