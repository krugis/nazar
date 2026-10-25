#!/bin/sh
# Install Nazar on a Debian/Ubuntu or RHEL-family server. Idempotent; run as root.
#
#   sudo sh install.sh                    # from PyPI (nazar-sec)
#   sudo sh install.sh --from /path/src   # from a source checkout or a wheel
#   sudo sh install.sh --from 'git+https://github.com/krugis/nazar-sec-nazar'
#   sudo sh install.sh --python /opt/python/bin/python3.12   # a specific interpreter
#
# It never starts Nazar in active mode: review the config and try a dry run first.
set -eu

SOURCE="nazar-sec"
PYTHON=""
PREFIX="/opt/nazar"
BIN="/usr/local/bin/nazar"
UNIT="/etc/systemd/system/nazar.service"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

while [ $# -gt 0 ]; do
    case "$1" in
        --from) SOURCE="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --python) PYTHON="$2"; shift 2 ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ "$(uname -s)" = "Linux" ] || die "Nazar supports Linux only"

# 1. Prerequisites
version_ok() { "$1" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; }
if [ -n "$PYTHON" ]; then
    [ -x "$PYTHON" ] && version_ok "$PYTHON" || die "--python $PYTHON is not Python 3.11+"
else
    for candidate in python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && version_ok "$candidate"; then
            PYTHON=$(command -v "$candidate"); break
        fi
    done
    [ -n "$PYTHON" ] || die "Python 3.11+ is required (e.g. apt install python3.12 python3.12-venv)"
fi
# The service runs as the nazar user, so the interpreter must not live in a private home.
case "$(readlink -f "$PYTHON")" in
    /root/*|/home/*) die "$PYTHON is under a home directory the nazar user cannot read; use --python with a system-wide interpreter" ;;
esac
"$PYTHON" -c 'import venv, ensurepip' 2>/dev/null ||
    die "the Python venv module is missing (e.g. apt install python3-venv)"
command -v cscli >/dev/null 2>&1 || die "cscli not found: install CrowdSec first (https://docs.crowdsec.net)"
if command -v curl >/dev/null 2>&1 && ! curl -fsS -m 3 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
    warn "Ollama is not answering on 127.0.0.1:11434 (install it from https://ollama.com)"
fi
say "using $PYTHON"

# 2. System user
if ! id nazar >/dev/null 2>&1; then
    say "creating system user nazar"
    NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
    useradd --system --home-dir /var/lib/nazar --no-create-home --shell "$NOLOGIN" nazar
fi

# 3. Install into a dedicated virtual environment
say "installing $SOURCE into $PREFIX/venv"
[ -x "$PREFIX/venv/bin/python" ] || "$PYTHON" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade pip
"$PREFIX/venv/bin/python" -m pip install --quiet --upgrade "$SOURCE"
ln -sf "$PREFIX/venv/bin/nazar" "$BIN"
chmod -R go-w "$PREFIX"

# 4. Config, secrets, CrowdSec machine, checks
say "running nazar init"
"$BIN" init || warn "nazar init reported problems; fix them and run 'sudo nazar init' again"

# 5. systemd unit: enabled, not started
if command -v systemctl >/dev/null 2>&1; then
    if [ -f "$HERE/nazar.service" ]; then
        install -m 0644 "$HERE/nazar.service" "$UNIT"
    else
        "$PREFIX/venv/bin/python" -c \
            'import importlib.resources as r; print(r.files("nazar").joinpath("data/nazar.service").read_text(), end="")' \
            > "$UNIT"
        chmod 0644 "$UNIT"
    fi
    systemctl daemon-reload
    systemctl enable nazar.service >/dev/null
    say "nazar.service installed and enabled (not started)"
fi

cat <<'NEXT'

Next steps:
  1. Edit /etc/nazar/config.yaml: add your own IPs to policy.allowlist_cidrs.
  2. Pull the model:   ollama pull hf.co/Nguuma/security-slm-unsloth-1.5b
  3. Try a dry run:    sudo -u nazar nazar run --dry-run --once
  4. Start the daemon: systemctl start nazar     (still dry-run until you set mode: active)
NEXT
