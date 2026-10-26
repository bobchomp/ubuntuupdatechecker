#!/usr/bin/env bash
# Install (or upgrade) update-checker on this machine.
#
#   sudo ./install.sh                     # interactive
#   sudo ./install.sh --machine optiplex  # start config from examples/optiplex.conf
#   sudo ./install.sh --reconfigure       # rewrite config + secrets even if they exist
#
# Re-running is safe: the program and systemd units are updated, an existing
# config and secret.env are kept unless --reconfigure is given.

set -euo pipefail

BIN=/usr/local/sbin/update-checker
SHARE=/usr/local/share/update-checker
CONF_DIR=/etc/update-checker
CONF=$CONF_DIR/config
SECRET=$CONF_DIR/secret.env
UNIT_DIR=/etc/systemd/system
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MACHINE=""
RECONFIGURE=0

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
need_tty() { [ -t 0 ] || die "$1 - run install.sh interactively in a terminal"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --machine) MACHINE="${2:-}"; shift 2 ;;
        --machine=*) MACHINE="${1#*=}"; shift ;;
        --reconfigure) RECONFIGURE=1; shift ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
command -v python3 >/dev/null || die "python3 is required (sudo apt install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
    || die "python3 3.8 or newer is required"
command -v systemctl >/dev/null || die "systemd is required"
for f in update_checker.py config/config.example config/secret.env.example \
         systemd/update-checker.service systemd/update-checker.timer; do
    [ -f "$SRC/$f" ] || die "missing $SRC/$f - run install.sh from the repository folder"
done

ask() {  # ask VAR "Prompt" "default"
    local __var=$1 __prompt=$2 __default=${3:-} __reply
    if [ -n "$__default" ]; then
        read -r -p "$__prompt [$__default]: " __reply || true
        __reply=${__reply:-$__default}
    else
        read -r -p "$__prompt: " __reply || true
    fi
    printf -v "$__var" '%s' "$__reply"
}

ask_secret() {  # ask_secret VAR "Prompt" - input is not echoed
    local __var=$1 __prompt=$2 __reply
    read -r -s -p "$__prompt: " __reply || true
    echo
    printf -v "$__var" '%s' "$__reply"
}

yesno() {  # yesno "Question" default(y|n)
    local reply def=${2:-n}
    read -r -p "$1 [$( [ "$def" = y ] && echo Y/n || echo y/N )]: " reply || true
    reply=${reply:-$def}
    [[ $reply =~ ^[Yy] ]]
}

sed_escape() { printf '%s' "$1" | sed -e 's/[\\|&]/\\&/g'; }

set_conf() {  # set_conf key value  (replaces "key = ..." in $CONF)
    local key=$1 val
    val=$(sed_escape "$2")
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${val}|" "$CONF"
}

# --- 1. Program -------------------------------------------------------------
info "Installing $BIN"
install -D -m 0755 -o root -g root "$SRC/update_checker.py" "$BIN"
install -d -m 0755 "$SHARE" "$SHARE/examples"
install -m 0644 "$SRC/config/config.example" "$SHARE/config.example"
install -m 0644 "$SRC/config/secret.env.example" "$SHARE/secret.env.example"
install -m 0644 "$SRC"/examples/*.conf "$SHARE/examples/"

# --- 2. Config --------------------------------------------------------------
install -d -m 0755 -o root -g root "$CONF_DIR"
if [ -f "$CONF" ] && [ "$RECONFIGURE" -eq 0 ]; then
    info "Keeping existing $CONF (use --reconfigure to recreate it)"
else
    need_tty "the config needs to be created"
    if [ -z "$MACHINE" ]; then
        host=$(hostname -s 2>/dev/null || hostname)
        default=generic
        for m in optiplex pihole droplet; do
            [[ ${host,,} == *"$m"* ]] && default=$m
        done
        echo
        echo "Which example config should this machine start from?"
        echo "  optiplex - home server, CasaOS + Docker, / and /mnt/storage"
        echo "  pihole   - Pi-hole box, no Docker"
        echo "  droplet  - DigitalOcean droplet with Docker"
        echo "  generic  - blank template"
        ask MACHINE "Machine type" "$default"
    fi
    case "$MACHINE" in
        optiplex|pihole|droplet) template="$SRC/examples/$MACHINE.conf" ;;
        generic) template="$SRC/config/config.example" ;;
        *) die "unknown machine type '$MACHINE' (optiplex, pihole, droplet, generic)" ;;
    esac
    [ -f "$CONF" ] && cp -p "$CONF" "$CONF.bak.$(date +%Y%m%d%H%M%S)" && info "Old config backed up"

    current_label=$(sed -n -E 's/^label[[:space:]]*=[[:space:]]*//p' "$template" | head -n1)
    [ "$MACHINE" = generic ] && current_label=$(hostname -s 2>/dev/null || hostname)
    current_from=$(sed -n -E 's/^from_address[[:space:]]*=[[:space:]]*//p' "$template" | head -n1)

    ask LABEL "Machine label for the email subject" "$current_label"
    RECIPIENT=""
    while [[ ! $RECIPIENT =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+([[:space:]]*,[[:space:]]*[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+)*$ ]]; do
        ask RECIPIENT "Recipient email address (comma-separate several)" ""
    done
    ask FROM "From address (must be on a domain verified in Resend)" "${current_from:-info@rossmackenzie.co.uk}"

    install -m 0644 -o root -g root "$template" "$CONF"
    set_conf label "$LABEL"
    set_conf recipient "$RECIPIENT"
    set_conf from_address "$FROM"
    info "Wrote $CONF"
fi

# --- 3. Secrets -------------------------------------------------------------
# The API key is typed here, stored only in $SECRET (root-only, mode 600) and
# only ever sent to api.resend.com when a report is emailed.
existing_key=""
existing_gh=""
if [ -f "$SECRET" ]; then
    existing_key=$(sed -n -E 's/^RESEND_API_KEY=//p' "$SECRET" | head -n1 | tr -d "\"'")
    existing_gh=$(sed -n -E 's/^GITHUB_TOKEN=//p' "$SECRET" | head -n1 | tr -d "\"'")
    [[ $existing_key == re_xxxx* ]] && existing_key=""
fi

RESEND_KEY=$existing_key
GH_TOKEN=$existing_gh
if [ -n "$existing_key" ] && [ "$RECONFIGURE" -eq 0 ]; then
    info "Keeping existing Resend API key in $SECRET"
else
    need_tty "the Resend API key needs to be entered"
    echo
    echo "Paste your Resend API key (https://resend.com/api-keys). It is stored only in"
    echo "$SECRET on this machine (root-only, chmod 600) and is not displayed."
    while :; do
        ask_secret RESEND_KEY "Resend API key${existing_key:+ (blank = keep current)}"
        [ -z "$RESEND_KEY" ] && RESEND_KEY=$existing_key
        [ -n "$RESEND_KEY" ] && break
        echo "An API key is required to send email (Ctrl-C to abort)."
    done
    [[ $RESEND_KEY == re_* ]] || echo "warning: Resend API keys normally start with 're_' - continuing anyway."
    echo
    echo "Optional: a GitHub token (no scopes needed) raises the GitHub API limit from"
    echo "60 to 5000 requests/hour. Press Enter to ${existing_gh:+keep the current one / }skip."
    ask_secret new_gh "GitHub token"
    [ -n "$new_gh" ] && GH_TOKEN=$new_gh
fi

old_umask=$(umask)
umask 077
tmp=$(mktemp "$CONF_DIR/.secret.XXXXXX")
{
    echo "# update-checker secrets - root only (chmod 600). Never commit this file."
    printf 'RESEND_API_KEY=%s\n' "$RESEND_KEY"
    printf 'GITHUB_TOKEN=%s\n' "$GH_TOKEN"
} > "$tmp"
umask "$old_umask"
chown root:root "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$SECRET"
unset RESEND_KEY GH_TOKEN existing_key existing_gh new_gh
info "Wrote $SECRET (root:root, 600)"

# --- 4. systemd -------------------------------------------------------------
info "Installing systemd service and timer"
install -m 0644 -o root -g root "$SRC/systemd/update-checker.service" "$UNIT_DIR/update-checker.service"
install -m 0644 -o root -g root "$SRC/systemd/update-checker.timer" "$UNIT_DIR/update-checker.timer"
systemctl daemon-reload
systemctl enable update-checker.timer >/dev/null 2>&1
systemctl restart update-checker.timer

echo
info "Installed."
systemctl list-timers update-checker.timer --no-pager 2>/dev/null | head -n 3 || true
cat <<EOF

  Config:       $CONF
  Secrets:      $SECRET
  Test:         sudo update-checker --dry-run
  Run now:      sudo systemctl start update-checker.service
  Logs:         journalctl -u update-checker.service

The first scheduled report is sent within a few minutes, then every 3 days.
EOF

echo
if [ -t 0 ] && yesno "Run a dry run now (prints the report here, sends nothing)?" n; then
    "$BIN" --dry-run || true
fi
