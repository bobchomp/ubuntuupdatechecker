#!/usr/bin/env bash
# Remove update-checker from this machine.
#
#   sudo ./uninstall.sh               # asks whether to delete /etc/update-checker
#   sudo ./uninstall.sh --purge       # also delete config + API key without asking
#   sudo ./uninstall.sh --keep-config # keep /etc/update-checker without asking

set -euo pipefail

CONF_DIR=/etc/update-checker
PURGE=ask

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE=yes; shift ;;
        --keep-config) PURGE=no; shift ;;
        -h|--help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"

info "Stopping and disabling the timer and service"
systemctl disable --now update-checker.timer >/dev/null 2>&1 || true
systemctl stop update-checker.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/update-checker.timer /etc/systemd/system/update-checker.service
systemctl daemon-reload
systemctl reset-failed update-checker.service update-checker.timer >/dev/null 2>&1 || true

info "Removing program files"
rm -f /usr/local/sbin/update-checker
rm -rf /usr/local/share/update-checker

if [ -d "$CONF_DIR" ]; then
    if [ "$PURGE" = ask ]; then
        read -r -p "Also delete $CONF_DIR (config and Resend API key)? [y/N]: " reply || true
        [[ ${reply:-n} =~ ^[Yy] ]] && PURGE=yes || PURGE=no
    fi
    if [ "$PURGE" = yes ]; then
        if command -v shred >/dev/null && [ -f "$CONF_DIR/secret.env" ]; then
            shred -u "$CONF_DIR/secret.env" || true
        fi
        rm -rf "$CONF_DIR"
        info "Deleted $CONF_DIR"
    else
        info "Kept $CONF_DIR (delete it later with: sudo rm -rf $CONF_DIR)"
    fi
fi

info "update-checker removed."
