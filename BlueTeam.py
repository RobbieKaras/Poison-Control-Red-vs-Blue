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
CTFD_TOKEN = "ctfd_7a87222d5e0ac284965d7d39ef5258a69666087655c6ce5910c2670ae727d07d"

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
POLL_SECONDS = 2
MAX_SEEN_REQUESTS = 5000

SQL_BLOCK_SCORE = 8
CMD_BLOCK_SCORE = 6
BRUTE_BLOCK_COUNT = 10
BRUTE_WINDOW_SECONDS = 30

SQL_LLM_REVIEW_SCORE = 4
USE_LLM = True

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


def block_ip(ip, attack_type, reason):
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

    nonce = get_ctfd_nonce()
    if not nonce:
        print("[-] Could not get nonce for scoring")
        return

    try:
        r = requests.post(
            f"{CTFD_URL}/api/v1/challenges/attempt",
            json={"challenge_id": challenge_id, "submission": flag},
            headers={
                "Authorization": f"Token {CTFD_TOKEN}",
                "Content-Type": "application/json",
                "CSRF-Token": nonce,
            },
            timeout=5,
        )
        result = r.json()
        if result.get("data", {}).get("status") == "correct":
            print(f"[+] BLUE TEAM SCORED for blocking {attack_type}")
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
            model="local-model",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a blue team analyst. "
                        "Classify the request as either ATTACK or BENIGN. "
                        "Only consider SQL injection. "
                        "Respond exactly in this format:\n"
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
    (r";\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh)\b", 5, "semicolon command chaining"),
    (r"\|\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh)\b", 5, "pipe command chaining"),
    (r"&&\s*(cat|ls|whoami|id|pwd|uname|curl|wget|nc|bash|sh)\b", 5, "and chaining"),
    (r"`[^`]+`", 5, "backtick execution"),
    (r"\$\([^)]+\)", 5, "subshell execution"),
    (r"/etc/passwd", 5, "passwd file target"),
    (r"flag2\.txt", 5, "flag file target"),
    (r"\bcat\b", 3, "cat command"),
    (r"\bls\b", 2, "ls command"),
    (r"\bwhoami\b", 3, "whoami command"),
    (r"\bid\b", 3, "id command"),
    (r"\buname\b", 2, "uname command"),
    (r"\bnc\b", 4, "netcat usage"),
    (r"\bwget\b", 4, "wget usage"),
    (r"\bcurl\b", 4, "curl usage"),
    (r"%0a", 4, "newline injection"),
    (r"\n", 4, "literal newline"),
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
                    continue

                print(f"[>] {ip} {method} {path[:100]}")

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
