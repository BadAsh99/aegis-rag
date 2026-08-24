#!/usr/bin/env bash
# AEGIS submission demo runner. Push-button, deterministic, zero live typing.
#
#   ./demo.sh              # Enter-to-advance between sections (narrate, then Enter)
#   DEMO_PAUSE=0 ./demo.sh # auto-advance on timers (hands-free, for a silent take)
#
# Configuration and secrets come from a gitignored .env, loaded below. Copy
# .env.example to .env and fill it in. Do NOT `export SOMETHING=<secret>` on the
# command line: that puts the value in your shell history and leaves it sitting in
# terminal scrollback, which is exactly how a key ends up in a recorded demo.
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true
# shellcheck disable=SC1091
if [ -f .env ]; then set -a; . ./.env; set +a; fi

# Quiet the sentence-transformers / HF Hub chatter. Progress bars and the
# unauthenticated-Hub warning print on every model load and read as errors in a
# recorded walkthrough.
export HF_HUB_DISABLE_PROGRESS_BARS=1
export HF_HUB_VERBOSITY=error
export HF_HUB_DISABLE_TELEMETRY=1
export TRANSFORMERS_VERBOSITY=error
export TOKENIZERS_PARALLELISM=false
export PYTHONWARNINGS=ignore

# PAUSE=1     Enter-to-advance. Narrate, press Enter, cut between takes.
# PAUSE=0     auto-advance on the short timers below. Fast silent run-through.
# PAUSE=narrate  auto-advance on timers matched to DEMO_NARRATION.md, so a single
#             unbroken take can be narrated live with no keyboard at all. Scale
#             everything with DEMO_SPEED (e.g. DEMO_SPEED=1.2 for 20% longer).
PAUSE="${DEMO_PAUSE:-1}"
SPEED="${DEMO_SPEED:-1}"
CY='\033[1;36m'; DIM='\033[2m'; RST='\033[0m'
banner(){ printf "\n${CY}========================================================================\n%s\n========================================================================${RST}\n\n" "$1"; }

# Seconds per section in narrate mode, in demo order: intro, attack, detection,
# action-gate, real-model, numbers, protegrity. Taken from the script's targets
# plus a few seconds of breathing room at each end.
NARRATE_SECS="60 120 90 75 95 105 155"
_sec_i=0
step(){
  case "$PAUSE" in
    1) printf "${DIM}"; read -rp "  (press Enter for the next section) "; printf "${RST}" ;;
    narrate)
      _sec_i=$((_sec_i + 1))
      s=$(echo "$NARRATE_SECS" | cut -d' ' -f"$_sec_i")
      [ -n "$s" ] || s=60
      sleep "$(echo "$s $SPEED" | awk '{printf "%.0f", $1 * $2}')"
      ;;
    *) sleep "${1:-3}" ;;
  esac
}

clear
banner "AEGIS  ·  Protegrity 2026 AI Pipeline Security Hackathon
Zero-exposure RAG.  Thesis: assume the prompt injection wins.
Gate the DATA, not the prompt. When the injection succeeds, the
attacker walks away with tokens, not people."
step 5

banner "1 of 6  ·  THE ATTACK  ·  same injection, four callers (blast radius)"
python attack_demo.py
step

banner "2 of 6  ·  DETECTION  ·  honeytoken tripwire + tamper-evident reveal ledger"
python tripwire_demo.py
step

banner "3 of 6  ·  THE ACTION-GATE  ·  even a compromised session cannot exfiltrate"
python action_gate_demo.py
step

banner "4 of 6  ·  REAL MODEL  ·  the injection through a real Claude"
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then python real_llm_demo.py; else echo "  (set ANTHROPIC_API_KEY to run the live-model segment)"; fi
step

banner "5 of 6  ·  THE NUMBERS  ·  privacy vs utility on real MiniLM embeddings"
python benchmark.py
step

banner "6 of 6  ·  REAL PROTEGRITY DEVELOPER EDITION  ·  protecting the data live"
python protegrity_showcase.py
step 5

banner "AEGIS  ·  gate the data, bind the reveal, gate the action.
Built on Protegrity Developer Edition.  Code + writeup: ashclements.dev"
