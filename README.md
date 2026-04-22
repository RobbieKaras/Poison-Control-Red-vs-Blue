# Poison Control — Red vs. Blue CTF Bots

Automated red team attacker and blue team defender bots built for a head-to-head CTF tournament targeting [DVWA (Damn Vulnerable Web Application)](https://github.com/digininja/DVWA).

## Overview

Each participant runs both bots simultaneously:
- **RedTeam.py** — attacks DVWA to capture flags (SQL injection, command injection, brute force)
- **BlueTeam.py** — monitors traffic logs and blocks attackers to earn defensive points

## Scoring

| Team | Challenge | Points |
|------|-----------|--------|
| Red | SQL Injection | 300 |
| Red | Command Injection | 200 |
| Red | Brute Force | 100 |
| Blue | Block SQL Injection | 200 |
| Blue | Block Command Injection | 150 |
| Blue | Block Brute Force | 100 |

## How It Works

### Red Team (`RedTeam.py`)
1. Logs into DVWA and sets security to low
2. **SQL Injection** — blasts fast UNION SELECT payloads, then autonomously enumerates `information_schema` to find the flag table/column without any hardcoding, then falls back to `zap_payloads.txt`
3. **Command Injection** — tries shell metacharacter payloads (`; | && $() ${IFS}` etc.) to read the flag file
4. **Brute Force** — tries ~100 common passwords against known usernames; `admin:password` is first

### Blue Team (`BlueTeam.py`)
1. Polls the Security API every second for new request logs
2. Blocks immediately on first access to any vulnerability endpoint (`/vulnerabilities/sqli/`, `/vulnerabilities/exec/`)
3. Detects attack-prep behavior (POST `/security.php`) and blocks before the first attack lands
4. Regex-based scoring for SQL and command injection patterns with evasion normalization
5. LLM review (via LM Studio) for borderline SQL injection cases
6. Brute force detection via sliding window rate limiting

## Files

| File | Description |
|------|-------------|
| `RedTeam.py` | Red team attack bot |
| `BlueTeam.py` | Blue team defense bot |
| `zap_payloads.txt` | SQL injection and command injection payloads (used as fallback) |

## Setup

### Requirements
```
pip install openai requests
```

### LM Studio (optional — used by BlueTeam LLM review)
- Download [LM Studio](https://lmstudio.ai/)
- Load a model (tested with `meta-llama-3.1-8b-instruct`)
- Start the local server on port `1234`

### Configuration
Update these constants at the top of each file before running:

**RedTeam.py**
```python
TARGET    = "http://<dvwa-host>:8080"
CTFD_URL  = "http://<ctfd-host>:8000"
CTFD_TOKEN = "ctfd_your_token_here"
```

**BlueTeam.py**
```python
API_URL    = "http://<security-api-host>:5000"
API_KEY    = "your_api_key"
CTFD_URL   = "http://<ctfd-host>:8000"
CTFD_TOKEN = "ctfd_your_token_here"
```

### Running
```bash
# Terminal 1 — start defender first
python BlueTeam.py

# Terminal 2 — start attacker
python RedTeam.py
```

## Architecture Notes

- Blue team is **reactive** — it polls logs after requests are made, so it cannot prevent the very first attack request from reaching DVWA. It compensates by blocking immediately on first endpoint access.
- Red team uses **autonomous SQL enumeration** — it discovers the flag's table and column name at runtime via `information_schema`, so it works even when the flag location changes between rounds.
- LLM calls are used for blue team confirmation only; red team LLM fallback is disabled by default (too slow for a 10-minute round).

## Tournament Format
- 1v1 bracket, 2 rounds per matchup (roles swap between rounds)
- 10 minutes per round or until all 3 flags are captured
- Flags rotate between rounds — no hardcoded flag values

## About

Built for the **Madison Artificial Intelligence Club** Security Bot Wars tournament. Each club member competes by submitting their own red and blue team bots to face off in a head-to-head bracket.
