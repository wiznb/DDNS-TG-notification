#!/usr/bin/env bash
# ============================================================
# ipchange Enterprise v6.4.1
# Lightweight VPS IPv4/IPv6 monitor + Telegram + optional CF DDNS
#
# Modes:
#   1) Cloudflare DDNS + Telegram notification
#   2) Telegram notification only
#
# Highlights:
#   - Config/state/logs unified in /root/ipchange
#   - systemd/OpenRC supervised daemon, no cron dependency
#   - IPv4/IPv6 independent monitoring and 3x "no IP" debounce
#   - Beijing time independent of host timezone
#   - Multi-source geo lookup with cache
#   - Cloudflare DDNS without jq dependency
#   - ipchange status shows heartbeat / next run / countdown
#   - ipchange monitor provides a live status panel (no external watch command)
#   - doctor/service-test/cf-test/geotest/test diagnostics
#   - configurable automatic log/cache retention and cleanup
# ============================================================

set -Eeuo pipefail

VERSION="6.4.1"
ROOT_DIR="/root/ipchange"
CONF="$ROOT_DIR/config.env"
STATE_DIR="$ROOT_DIR/state"
LOG_DIR="$ROOT_DIR/logs"
INSTALL_LOG="$LOG_DIR/install.log"
SETUP_COPY="$ROOT_DIR/install.sh"
BIN="/usr/local/bin/ipchange"

SYSTEMD_UNIT="/etc/systemd/system/ipchange.service"
OPENRC_SERVICE="/etc/init.d/ipchange"

LEGACY_CONF_1="/etc/ipchange/config.env"
LEGACY_STATE_1="/var/lib/ipchange"
LEGACY_LOG_1="/var/log/ipchange"
LEGACY_CONF_2="/opt/ipchange/config.conf"
LEGACY_DDNS="/root/ddns/config.env"

need_root() {
    [ "$(id -u)" -eq 0 ] || {
        echo "❌ 请使用 root 运行：sudo bash $0"
        exit 1
    }
}

say() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
is_alpine() { [ -f /etc/alpine-release ] || have apk; }

on_error() {
    local rc=$? line="${BASH_LINENO[0]:-?}"
    printf '\n❌ 安装器发生未预期错误：exit=%s line=%s\n' "$rc" "$line" >&2
    printf '   安装日志：%s\n' "$INSTALL_LOG" >&2
    exit "$rc"
}
trap on_error ERR

tty_printf() {
    if [ -w /dev/tty ] 2>/dev/null; then
        printf "$@" > /dev/tty
    else
        printf "$@" >&2
    fi
}

read_tty() {
    local __var="$1" __line=""
    if [ -r /dev/tty ] 2>/dev/null; then
        IFS= read -r __line < /dev/tty || __line=""
    else
        IFS= read -r __line || __line=""
    fi
    printf -v "$__var" '%s' "$__line"
}

read_tty_secret() {
    local __var="$1" __line=""
    if [ -r /dev/tty ] 2>/dev/null; then
        IFS= read -r -s __line < /dev/tty || __line=""
    else
        IFS= read -r -s __line || __line=""
    fi
    printf -v "$__var" '%s' "$__line"
}

prompt_keep() {
    local prompt="$1" old="$2" out=""
    tty_printf "%s [%s]: " "$prompt" "${old:-无}"
    read_tty out
    [ -n "$out" ] || out="$old"
    printf '%s' "$out"
}

prompt_secret_keep() {
    local prompt="$1" old="$2" out=""
    if [ -n "$old" ]; then
        tty_printf "%s（回车保留现有）: " "$prompt"
    else
        tty_printf "%s: " "$prompt"
    fi
    read_tty_secret out
    tty_printf '\n'
    [ -n "$out" ] || out="$old"
    printf '%s' "$out"
}

run_with_progress() {
    local label="$1"; shift
    local tmp pid rc=0 start now elapsed width=28 block=6 pos=0 dir=1 i bar

    mkdir -p "$LOG_DIR"
    tmp="$(mktemp /tmp/ipchange-progress.XXXXXX)"
    start="$(date +%s)"

    "$@" >"$tmp" 2>&1 &
    pid=$!

    if [ -t 1 ]; then
        while kill -0 "$pid" 2>/dev/null; do
            now="$(date +%s)"
            elapsed=$((now - start))
            bar=""
            for ((i=0; i<width; i++)); do
                if [ "$i" -ge "$pos" ] && [ "$i" -lt $((pos + block)) ]; then
                    bar="${bar}="
                else
                    bar="${bar}."
                fi
            done
            printf '\r⏳ [%-28s] %s  %ss' "$bar" "$label" "$elapsed"
            if [ "$dir" -eq 1 ]; then
                pos=$((pos + 1))
                [ "$pos" -ge $((width - block)) ] && dir=-1
            else
                pos=$((pos - 1))
                [ "$pos" -le 0 ] && dir=1
            fi
            sleep 0.20
        done
    else
        printf '⏳ %s ...\n' "$label"
    fi

    set +e
    wait "$pid"
    rc=$?
    set -e

    now="$(date +%s)"
    elapsed=$((now - start))
    {
        printf '\n===== [%s] %s =====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$label"
        cat "$tmp"
    } >> "$INSTALL_LOG" 2>/dev/null || true

    if [ "$rc" -eq 0 ]; then
        [ -t 1 ] && printf '\r✅ [============================] %s  完成 (%ss)\n' "$label" "$elapsed" \
                 || printf '✅ %s 完成 (%ss)\n' "$label" "$elapsed"
    else
        [ -t 1 ] && printf '\r❌ [============================] %s  失败 (%ss)\n' "$label" "$elapsed" \
                 || printf '❌ %s 失败 (%ss)\n' "$label" "$elapsed"
        say "---- 最近错误输出 ----"
        tail -n 20 "$tmp" 2>/dev/null || true
        say "----------------------"
    fi

    rm -f "$tmp"
    return "$rc"
}

stage() {
    local current="$1" total="$2" label="$3" width=24 filled i bar=""
    filled=$((current * width / total))
    for ((i=0; i<filled; i++)); do bar="${bar}#"; done
    for ((i=filled; i<width; i++)); do bar="${bar}."; done
    printf '\n[%s] %s/%s  %s\n' "$bar" "$current" "$total" "$label"
}

mkdirs() {
    local stamp
    mkdir -p "$ROOT_DIR" "$STATE_DIR" "$LOG_DIR"
    chmod 700 "$ROOT_DIR" "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true

    # Keep each installer run separate so old installation logs can later be
    # deleted by the same retention policy.
    if [ -s "$INSTALL_LOG" ]; then
        stamp="$(TZ=Asia/Shanghai date '+%Y%m%d_%H%M%S' 2>/dev/null || date '+%Y%m%d_%H%M%S')"
        mv "$INSTALL_LOG" "$LOG_DIR/install_${stamp}_$$.log" 2>/dev/null || true
    fi
    touch "$INSTALL_LOG"
    chmod 600 "$INSTALL_LOG" 2>/dev/null || true
}

install_deps() {
    say "正在检查基础依赖..."
    if have bash && have curl; then
        say "✅ bash/curl 已存在，无需安装额外 JSON 工具。"
        return 0
    fi

    if have apt-get; then
        run_with_progress "刷新 apt 软件索引" env DEBIAN_FRONTEND=noninteractive apt-get update -o Acquire::Retries=3 || true
        run_with_progress "安装 bash/curl/证书/时区" env DEBIAN_FRONTEND=noninteractive apt-get install -y bash curl ca-certificates tzdata \
            || run_with_progress "安装基础依赖" env DEBIAN_FRONTEND=noninteractive apt-get install -y bash curl ca-certificates
    elif have dnf; then
        run_with_progress "安装 bash/curl/证书/时区" dnf install -y bash curl ca-certificates tzdata
    elif have yum; then
        run_with_progress "安装 bash/curl/证书/时区" yum install -y bash curl ca-certificates tzdata
    elif have apk; then
        run_with_progress "安装 bash/curl/证书/时区" apk add --no-cache bash curl ca-certificates tzdata \
            || run_with_progress "安装基础依赖" apk add --no-cache bash curl ca-certificates
    elif have pacman; then
        run_with_progress "安装 bash/curl/证书/时区" pacman -Sy --noconfirm bash curl ca-certificates tzdata
    elif have zypper; then
        run_with_progress "安装 bash/curl/证书/时区" zypper --non-interactive install bash curl ca-certificates timezone
    else
        say "❌ 未识别包管理器，请先安装 bash 和 curl。"
        return 1
    fi

    have bash && have curl
}

migrate_layout() {
    local f base copied=0

    if [ ! -f "$CONF" ] && [ -f "$LEGACY_CONF_1" ]; then
        cp -p "$LEGACY_CONF_1" "$CONF" 2>/dev/null || true
        [ -f "$CONF" ] && copied=1
    fi

    if [ -d "$LEGACY_STATE_1" ]; then
        for f in "$LEGACY_STATE_1"/*; do
            [ -e "$f" ] || continue
            base="$(basename "$f")"
            [ -e "$STATE_DIR/$base" ] || cp -a "$f" "$STATE_DIR/$base" 2>/dev/null || true
        done
        copied=1
    fi

    if [ -d "$LEGACY_LOG_1" ]; then
        for f in "$LEGACY_LOG_1"/*; do
            [ -e "$f" ] || continue
            base="$(basename "$f")"
            [ -e "$LOG_DIR/$base" ] || cp -a "$f" "$LOG_DIR/$base" 2>/dev/null || true
        done
        copied=1
    fi

    [ "$copied" -eq 0 ] || say "ℹ️ 已迁移旧版数据到 $ROOT_DIR（旧目录暂不删除）。"
}

OLD_MODE=""
OLD_TOKEN=""
OLD_CHAT=""
OLD_NAME=""
OLD_INTERVAL="1"
OLD_NO_THRESHOLD="3"
OLD_ENABLE4="1"
OLD_ENABLE6="1"
OLD_CF_AUTH_MODE=""
OLD_CF_TOKEN=""
OLD_CF_EMAIL=""
OLD_CF_KEY=""
OLD_CF_ZONE=""
OLD_CF_RECORD=""
OLD_CF_PROXIED="false"
OLD_CF_TTL="1"
OLD_CLEANUP_DAYS="30"

load_defaults() {
    local src=""

    if [ -f "$CONF" ]; then
        src="$CONF"
    elif [ -f "$LEGACY_CONF_1" ]; then
        src="$LEGACY_CONF_1"
    elif [ -f "$LEGACY_CONF_2" ]; then
        src="$LEGACY_CONF_2"
    fi

    if [ -n "$src" ]; then
        # shellcheck disable=SC1090
        . "$src" 2>/dev/null || true
        OLD_MODE="${MODE:-}"
        OLD_TOKEN="${BOT_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"
        OLD_CHAT="${CHAT_ID:-${TELEGRAM_CHAT_ID:-}}"
        OLD_NAME="${VPS_NAME:-}"
        OLD_INTERVAL="${INTERVAL:-1}"
        OLD_NO_THRESHOLD="${NO_THRESHOLD:-3}"
        OLD_ENABLE4="${ENABLE_IPV4:-1}"
        OLD_ENABLE6="${ENABLE_IPV6:-1}"
        OLD_CF_AUTH_MODE="${CF_AUTH_MODE:-}"
        OLD_CF_TOKEN="${CF_API_TOKEN:-}"
        OLD_CF_EMAIL="${CF_EMAIL:-}"
        OLD_CF_KEY="${CF_API_KEY:-}"
        OLD_CF_ZONE="${CF_ZONE_NAME:-${CFZONE_NAME:-}}"
        OLD_CF_RECORD="${CF_RECORD_NAME:-${CFRECORD_NAME:-}}"
        OLD_CF_PROXIED="${CF_PROXIED:-${PROXIED:-false}}"
        OLD_CF_TTL="${CF_TTL:-${TTL:-1}}"
        OLD_CLEANUP_DAYS="${CLEANUP_DAYS:-30}"
    fi

    if [ -f "$LEGACY_DDNS" ]; then
        # shellcheck disable=SC1090
        . "$LEGACY_DDNS" 2>/dev/null || true
        [ -n "$OLD_CF_AUTH_MODE" ] || OLD_CF_AUTH_MODE="${CF_AUTH_MODE:-}"
        [ -n "$OLD_CF_TOKEN" ] || OLD_CF_TOKEN="${CF_API_TOKEN:-}"
        [ -n "$OLD_CF_EMAIL" ] || OLD_CF_EMAIL="${CF_EMAIL:-}"
        [ -n "$OLD_CF_KEY" ] || OLD_CF_KEY="${CF_API_KEY:-}"
        [ -n "$OLD_CF_ZONE" ] || OLD_CF_ZONE="${CFZONE_NAME:-}"
        [ -n "$OLD_CF_RECORD" ] || OLD_CF_RECORD="${CFRECORD_NAME:-}"
    fi

    [ -n "$OLD_NAME" ] || OLD_NAME="$(hostname 2>/dev/null || echo VPS)"
}

normalize_int() {
    local n="$1" min="$2" max="$3" def="$4"
    case "$n" in ''|*[!0-9]*) n="$def" ;; esac
    [ "$n" -lt "$min" ] && n="$min"
    [ "$n" -gt "$max" ] && n="$max"
    printf '%s' "$n"
}

choose_cleanup_days() {
    local old="${1:-30}" opt="" custom="" current_label=""

    case "$old" in
        ''|*[!0-9]*) old=30 ;;
    esac

    if [ "$old" -eq 0 ] 2>/dev/null; then
        current_label="关闭"
    else
        current_label="${old} 天"
    fi

    while :; do
        # IMPORTANT:
        # This function is called as CLEANUP_DAYS="$(choose_cleanup_days ...)".
        # Therefore stdout must contain ONLY the final numeric return value.
        # All menu/prompt/error text goes directly to the controlling TTY.
        tty_printf '\n'
        tty_printf '%s\n' "自动清理日志 / 可重建缓存："
        tty_printf '%s\n' "  1) 保留 3 天"
        tty_printf '%s\n' "  2) 保留 7 天"
        tty_printf '%s\n' "  3) 保留 15 天"
        tty_printf '%s\n' "  4) 保留 30 天（推荐）"
        tty_printf '%s\n' "  5) 保留 60 天"
        tty_printf '%s\n' "  6) 保留 90 天"
        tty_printf '%s\n' "  7) 自定义保留天数"
        tty_printf '%s\n' "  0) 关闭自动清理"
        tty_printf '\n'
        tty_printf "请选择 [0-7]（当前：%s；直接回车保留）: " "$current_label"
        read_tty opt

        if [ -z "$opt" ]; then
            printf '%s' "$old"
            return 0
        fi

        case "$opt" in
            0)
                printf '0'
                return 0
                ;;
            1)
                printf '3'
                return 0
                ;;
            2)
                printf '7'
                return 0
                ;;
            3)
                printf '15'
                return 0
                ;;
            4)
                printf '30'
                return 0
                ;;
            5)
                printf '60'
                return 0
                ;;
            6)
                printf '90'
                return 0
                ;;
            7)
                while :; do
                    tty_printf "请输入自定义保留天数 [1-3650]（例如 45）: "
                    read_tty custom
                    case "$custom" in
                        ''|*[!0-9]*)
                            tty_printf '%s\n' "❌ 请输入 1-3650 之间的整数。"
                            continue
                            ;;
                    esac
                    if [ "$custom" -lt 1 ] || [ "$custom" -gt 3650 ]; then
                        tty_printf '%s\n' "❌ 超出范围，请输入 1-3650。"
                        continue
                    fi
                    printf '%s' "$custom"
                    return 0
                done
                ;;
            *)
                tty_printf '%s\n' "❌ 无效选择，请输入 0、1、2、3、4、5、6 或 7。"
                ;;
        esac
    done
}

write_config() {
    local modeopt MODE_IN TOKEN CHAT NAME INTERVAL NO_THRESHOLD CLEANUP_DAYS ipopt ENABLE4 ENABLE6
    local authopt CF_AUTH_MODE_IN="" CF_TOKEN="" CF_EMAIL_IN="" CF_KEY=""
    local CF_ZONE="" CF_RECORD="" CF_PROXIED_IN="false" CF_TTL_IN="1"

    say
    say "=================================================="
    say " ipchange Enterprise v$VERSION 配置"
    say "=================================================="
    say "请选择运行模式："
    say "  1) Cloudflare DDNS 更新 + Telegram IP变化通知"
    say "  2) 仅 Telegram IP变化通知"

    if [ "$OLD_MODE" = "notify" ]; then
        tty_printf "请选择 [1/2]（当前 2）: "
    else
        tty_printf "请选择 [1/2]（当前 1）: "
    fi
    read_tty modeopt
    [ -n "$modeopt" ] || { [ "$OLD_MODE" = "notify" ] && modeopt=2 || modeopt=1; }
    [ "$modeopt" = "2" ] && MODE_IN="notify" || MODE_IN="ddns"

    TOKEN="$(prompt_secret_keep "Telegram Bot Token" "$OLD_TOKEN")"
    CHAT="$(prompt_keep "Telegram Chat ID/群ID" "$OLD_CHAT")"
    NAME="$(prompt_keep "本机 VPS 名称/备注" "$OLD_NAME")"
    INTERVAL="$(prompt_keep "检测间隔（分钟，1~60）" "$OLD_INTERVAL")"
    INTERVAL="$(normalize_int "$INTERVAL" 1 60 1)"
    NO_THRESHOLD="$(prompt_keep "连续多少次获取不到 IP 才确认“无”" "$OLD_NO_THRESHOLD")"
    NO_THRESHOLD="$(normalize_int "$NO_THRESHOLD" 2 10 3)"
    CLEANUP_DAYS="$(choose_cleanup_days "$OLD_CLEANUP_DAYS")"

    [ -n "$TOKEN" ] || { say "❌ Bot Token 不能为空。"; return 1; }
    [ -n "$CHAT" ] || { say "❌ Chat ID 不能为空。"; return 1; }
    [ -n "$NAME" ] || NAME="VPS"

    say
    say "监控协议："
    say "  1) 仅 IPv4"
    say "  2) 仅 IPv6"
    say "  3) IPv4 + IPv6"

    local old_ipopt=3
    [ "$OLD_ENABLE4" = "1" ] && [ "$OLD_ENABLE6" != "1" ] && old_ipopt=1
    [ "$OLD_ENABLE4" != "1" ] && [ "$OLD_ENABLE6" = "1" ] && old_ipopt=2
    tty_printf "请选择 [1/2/3]（当前 %s）: " "$old_ipopt"
    read_tty ipopt
    [ -n "$ipopt" ] || ipopt="$old_ipopt"

    case "$ipopt" in
        1) ENABLE4=1; ENABLE6=0 ;;
        2) ENABLE4=0; ENABLE6=1 ;;
        *) ENABLE4=1; ENABLE6=1 ;;
    esac

    if [ "$MODE_IN" = "ddns" ]; then
        say
        say "ℹ️ Cloudflare 模块不依赖 jq。"
        say "Cloudflare 认证："
        say "  1) API Token（推荐）"
        say "  2) Global API Key"

        local old_auth=1
        [ "$OLD_CF_AUTH_MODE" = "global" ] && old_auth=2
        tty_printf "请选择 [1/2]（当前 %s）: " "$old_auth"
        read_tty authopt
        [ -n "$authopt" ] || authopt="$old_auth"

        if [ "$authopt" = "2" ]; then
            CF_AUTH_MODE_IN="global"
            CF_EMAIL_IN="$(prompt_keep "Cloudflare 邮箱" "$OLD_CF_EMAIL")"
            CF_KEY="$(prompt_secret_keep "Cloudflare Global API Key" "$OLD_CF_KEY")"
            [ -n "$CF_EMAIL_IN" ] || { say "❌ Cloudflare 邮箱不能为空。"; return 1; }
            [ -n "$CF_KEY" ] || { say "❌ Global API Key 不能为空。"; return 1; }
        else
            CF_AUTH_MODE_IN="token"
            CF_TOKEN="$(prompt_secret_keep "Cloudflare API Token" "$OLD_CF_TOKEN")"
            [ -n "$CF_TOKEN" ] || { say "❌ API Token 不能为空。"; return 1; }
        fi

        CF_ZONE="$(prompt_keep "Cloudflare Zone（如 example.com）" "$OLD_CF_ZONE")"
        CF_RECORD="$(prompt_keep "DDNS 记录名（如 home.example.com）" "$OLD_CF_RECORD")"
        CF_PROXIED_IN="$(prompt_keep "Cloudflare 橙云代理 true/false" "$OLD_CF_PROXIED")"
        CF_TTL_IN="$(prompt_keep "TTL（1=自动）" "$OLD_CF_TTL")"

        [ -n "$CF_ZONE" ] || { say "❌ Zone 不能为空。"; return 1; }
        [ -n "$CF_RECORD" ] || { say "❌ Record 不能为空。"; return 1; }
        case "$CF_PROXIED_IN" in true|false) ;; *) CF_PROXIED_IN=false ;; esac
        CF_TTL_IN="$(normalize_int "$CF_TTL_IN" 1 86400 1)"
    fi

    umask 077
    {
        echo "# ipchange Enterprise v$VERSION"
        printf 'MODE=%q\n' "$MODE_IN"
        printf 'BOT_TOKEN=%q\n' "$TOKEN"
        printf 'CHAT_ID=%q\n' "$CHAT"
        printf 'VPS_NAME=%q\n' "$NAME"
        printf 'INTERVAL=%q\n' "$INTERVAL"
        printf 'NO_THRESHOLD=%q\n' "$NO_THRESHOLD"
        printf 'ENABLE_IPV4=%q\n' "$ENABLE4"
        printf 'ENABLE_IPV6=%q\n' "$ENABLE6"
        printf 'GEO_ENABLE=%q\n' "1"
        printf 'CLEANUP_DAYS=%q\n' "$CLEANUP_DAYS"
        printf 'CF_AUTH_MODE=%q\n' "$CF_AUTH_MODE_IN"
        printf 'CF_API_TOKEN=%q\n' "$CF_TOKEN"
        printf 'CF_EMAIL=%q\n' "$CF_EMAIL_IN"
        printf 'CF_API_KEY=%q\n' "$CF_KEY"
        printf 'CF_ZONE_NAME=%q\n' "$CF_ZONE"
        printf 'CF_RECORD_NAME=%q\n' "$CF_RECORD"
        printf 'CF_PROXIED=%q\n' "$CF_PROXIED_IN"
        printf 'CF_TTL=%q\n' "$CF_TTL_IN"
    } > "$CONF"
    chmod 600 "$CONF"
    rm -f "$STATE_DIR/cf_zone_id" 2>/dev/null || true

    say
    say "✅ 配置已保存：$CONF"
    say "✅ 模式：$([ "$MODE_IN" = "ddns" ] && echo 'DDNS + 通知' || echo '仅通知')"
    if [ "$CLEANUP_DAYS" -eq 0 ]; then
        say "✅ 自动清理：关闭"
    else
        say "✅ 日志/缓存自动保留：${CLEANUP_DAYS} 天"
    fi
}

install_program() {
cat > "$BIN" <<'EOS'
#!/usr/bin/env bash
set -u
set -o pipefail

VERSION="6.4.1"
ROOT_DIR="/root/ipchange"
CONF="$ROOT_DIR/config.env"
STATE_DIR="$ROOT_DIR/state"
LOG_DIR="$ROOT_DIR/logs"
SETUP="$ROOT_DIR/install.sh"

HISTORY="$STATE_DIR/history.log"
GEO_CACHE="$STATE_DIR/geo.cache"
LOCKDIR="$STATE_DIR/.lock"
LAST_CHECK="$STATE_DIR/last_check"
LAST_CHECK_EPOCH="$STATE_DIR/last_check_epoch"
LAST_OK="$STATE_DIR/last_ok"
NEXT_CHECK_EPOCH="$STATE_DIR/next_check_epoch"
ZONE_CACHE="$STATE_DIR/cf_zone_id"
PIDFILE="$STATE_DIR/daemon.pid"
LAST_CF_ATTEMPT="$STATE_DIR/cf_last_attempt"

NO4_FILE="$STATE_DIR/no_ipv4.count"
NO6_FILE="$STATE_DIR/no_ipv6.count"
CF4_FAIL="$STATE_DIR/cf_ipv4.failed"
CF6_FAIL="$STATE_DIR/cf_ipv6.failed"

TG_LAST_OK="$STATE_DIR/telegram_last_ok"
TG_LAST_OK_EPOCH="$STATE_DIR/telegram_last_ok_epoch"
TG_LAST_ERR="$STATE_DIR/telegram_last_error"

CLEANUP_LAST="$STATE_DIR/cleanup_last"
CLEANUP_LAST_EPOCH="$STATE_DIR/cleanup_last_epoch"
CACHE_PURGE_EPOCH="$STATE_DIR/cache_purge_epoch"
LOG_DAY_FILE="$STATE_DIR/log_day"

LOG_FILE="$LOG_DIR/ipchange.log"
CF_API_BASE="https://api.cloudflare.com/client/v4"

mkdir -p "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true

[ -f "$CONF" ] || {
    echo "❌ 找不到配置：$CONF"
    echo "请重新运行安装器，或执行：ipchange setup"
    exit 1
}

# shellcheck disable=SC1090
. "$CONF"

MODE="${MODE:-notify}"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"
VPS_NAME="${VPS_NAME:-VPS}"
INTERVAL="${INTERVAL:-1}"
NO_THRESHOLD="${NO_THRESHOLD:-3}"
ENABLE_IPV4="${ENABLE_IPV4:-1}"
ENABLE_IPV6="${ENABLE_IPV6:-1}"
GEO_ENABLE="${GEO_ENABLE:-1}"
CLEANUP_DAYS="${CLEANUP_DAYS:-30}"

CF_AUTH_MODE="${CF_AUTH_MODE:-token}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_EMAIL="${CF_EMAIL:-}"
CF_API_KEY="${CF_API_KEY:-}"
CF_ZONE_NAME="${CF_ZONE_NAME:-}"
CF_RECORD_NAME="${CF_RECORD_NAME:-}"
CF_PROXIED="${CF_PROXIED:-false}"
CF_TTL="${CF_TTL:-1}"

case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=1 ;; esac
[ "$INTERVAL" -lt 1 ] && INTERVAL=1
[ "$INTERVAL" -gt 60 ] && INTERVAL=60
case "$NO_THRESHOLD" in ''|*[!0-9]*) NO_THRESHOLD=3 ;; esac
[ "$NO_THRESHOLD" -lt 2 ] && NO_THRESHOLD=3
case "$CLEANUP_DAYS" in ''|*[!0-9]*) CLEANUP_DAYS=30 ;; esac
[ "$CLEANUP_DAYS" -lt 0 ] && CLEANUP_DAYS=30
[ "$CLEANUP_DAYS" -gt 3650 ] && CLEANUP_DAYS=3650

if [ -e /usr/share/zoneinfo/Asia/Shanghai ]; then
    BJ_TZ="Asia/Shanghai"
else
    BJ_TZ="CST-8"
fi

bj_now() { TZ="$BJ_TZ" date "+%Y-%m-%d %H:%M:%S"; }
bj_day() { TZ="$BJ_TZ" date "+%Y-%m-%d"; }
epoch_now() { date "+%s"; }

epoch_to_bj() {
    local e="$1"
    case "$e" in ''|*[!0-9]*) printf '未知'; return ;; esac
    TZ="$BJ_TZ" date -d "@$e" "+%Y-%m-%d %H:%M:%S" 2>/dev/null \
        || TZ="$BJ_TZ" date -r "$e" "+%Y-%m-%d %H:%M:%S" 2>/dev/null \
        || printf '未知'
}

human_seconds() {
    local s="$1" d h m
    case "$s" in ''|*[!0-9-]*) printf '未知'; return ;; esac
    [ "$s" -lt 0 ] && s=0
    d=$((s/86400)); h=$(((s%86400)/3600)); m=$(((s%3600)/60))
    if [ "$d" -gt 0 ]; then
        printf '%s天%s小时%s分钟' "$d" "$h" "$m"
    elif [ "$h" -gt 0 ]; then
        printf '%s小时%s分钟' "$h" "$m"
    elif [ "$m" -gt 0 ]; then
        printf '%s分钟%s秒' "$m" "$((s%60))"
    else
        printf '%s秒' "$s"
    fi
}

file_mtime_epoch() {
    local f="$1" x=""
    x="$(stat -c %Y "$f" 2>/dev/null || true)"
    if ! printf '%s' "$x" | grep -Eq '^[0-9]+$'; then
        x="$(stat -f %m "$f" 2>/dev/null || true)"
    fi
    printf '%s\n' "$x"
}

rotate_runtime_log() {
    local today last target
    today="$(bj_day)"
    last="$(cat "$LOG_DAY_FILE" 2>/dev/null || true)"

    if [ -z "$last" ]; then
        printf '%s\n' "$today" > "$LOG_DAY_FILE"
        return 0
    fi

    [ "$last" = "$today" ] && return 0

    if [ -s "$LOG_FILE" ]; then
        target="$LOG_DIR/ipchange_${last}.log"
        if [ -f "$target" ]; then
            cat "$LOG_FILE" >> "$target" 2>/dev/null || true
            : > "$LOG_FILE"
        else
            mv "$LOG_FILE" "$target" 2>/dev/null || true
        fi
    fi
    printf '%s\n' "$today" > "$LOG_DAY_FILE"
}

file_is_older_than_days() {
    local f="$1" days="$2" mt now
    [ -f "$f" ] || return 1
    mt="$(file_mtime_epoch "$f")"
    printf '%s' "$mt" | grep -Eq '^[0-9]+$' || return 1
    now="$(epoch_now)"
    [ $((now - mt)) -ge $((days * 86400)) ]
}

cleanup_storage() {
    local quiet="${1:-0}" now last_cache deleted=0 cache_deleted=0 f
    now="$(epoch_now)"

    if [ "$CLEANUP_DAYS" -eq 0 ]; then
        [ "$quiet" = "1" ] || echo "ℹ️ 自动清理已关闭。"
        return 0
    fi

    rotate_runtime_log

    # Delete only archived logs. Never remove the live log file that the
    # running service is currently writing to.
    for f in "$LOG_DIR"/ipchange_*.log "$LOG_DIR"/install_*.log; do
        [ -f "$f" ] || continue
        if file_is_older_than_days "$f" "$CLEANUP_DAYS"; then
            rm -f "$f" 2>/dev/null && deleted=$((deleted + 1))
        fi
    done

    # telegram_last_error is diagnostic-only and can be regenerated.
    if [ -f "$TG_LAST_ERR" ] && file_is_older_than_days "$TG_LAST_ERR" "$CLEANUP_DAYS"; then
        rm -f "$TG_LAST_ERR" 2>/dev/null || true
        deleted=$((deleted + 1))
    fi

    # Geo cache has no critical state. Purge it once per retention period so
    # old location data does not remain forever; it is rebuilt on demand.
    last_cache="$(cat "$CACHE_PURGE_EPOCH" 2>/dev/null || echo 0)"
    case "$last_cache" in ''|*[!0-9]*) last_cache=0 ;; esac
    if [ "$last_cache" -eq 0 ] && [ -f "$GEO_CACHE" ]; then
        last_cache="$(file_mtime_epoch "$GEO_CACHE")"
        case "$last_cache" in ''|*[!0-9]*) last_cache=0 ;; esac
    fi
    if [ "$last_cache" -eq 0 ] || [ $((now - last_cache)) -ge $((CLEANUP_DAYS * 86400)) ]; then
        if [ -f "$GEO_CACHE" ]; then
            rm -f "$GEO_CACHE" 2>/dev/null || true
            cache_deleted=1
        fi
        printf '%s\n' "$now" > "$CACHE_PURGE_EPOCH"
    fi

    printf '%s\n' "$(bj_now)" > "$CLEANUP_LAST"
    printf '%s\n' "$now" > "$CLEANUP_LAST_EPOCH"

    [ "$quiet" = "1" ] || {
        echo "✅ 清理完成：保留策略 ${CLEANUP_DAYS} 天"
        echo "   已删除旧日志/错误缓存：${deleted} 个"
        [ "$cache_deleted" -eq 1 ] && echo "   已刷新地区缓存：是" || echo "   已刷新地区缓存：否"
        echo "   最近清理：$(cat "$CLEANUP_LAST")"
        echo "   不会删除：IP基线、DDNS状态、心跳、失败计数、当前配置"
    }
}

auto_cleanup_if_due() {
    local now last
    [ "$CLEANUP_DAYS" -gt 0 ] || return 0
    now="$(epoch_now)"
    last="$(cat "$CLEANUP_LAST_EPOCH" 2>/dev/null || echo 0)"
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    # Run retention maintenance at most once per 24 hours.
    if [ "$last" -eq 0 ] || [ $((now - last)) -ge 86400 ]; then
        cleanup_storage 1
    fi
}

log() {
    local level="$1"; shift
    rotate_runtime_log
    printf '[%s] [%s] %s\n' "$(bj_now)" "$level" "$*" >> "$LOG_FILE"
    local size
    size="$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)"
    case "$size" in ''|*[!0-9]*) size=0 ;; esac
    # Live log also has a hard size safety cap even before daily rotation.
    if [ "$size" -gt 2097152 ]; then
        tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp.$$" 2>/dev/null \
            && mv "$LOG_FILE.tmp.$$" "$LOG_FILE"
    fi
}

trim() { printf '%s' "$1" | tr -d '\r\n\t '; }

valid4() {
    local ip="$1" a b c d n
    IFS=. read -r a b c d <<EOF
$ip
EOF
    [ -n "${d:-}" ] || return 1
    for n in "$a" "$b" "$c" "$d"; do
        case "$n" in ''|*[!0-9]*) return 1 ;; esac
        [ "$n" -ge 0 ] 2>/dev/null && [ "$n" -le 255 ] 2>/dev/null || return 1
    done
}

valid6() {
    case "$1" in
        *:*) printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:.]+$' ;;
        *) return 1 ;;
    esac
}

get4() {
    local u x
    for u in \
        https://api.ipify.org \
        https://ipv4.icanhazip.com \
        https://ifconfig.co/ip \
        https://1.1.1.1/cdn-cgi/trace
    do
        if [ "$u" = "https://1.1.1.1/cdn-cgi/trace" ]; then
            x="$(curl -4 -fsS --retry 1 --connect-timeout 3 --max-time 6 "$u" 2>/dev/null \
                | awk -F= '/^ip=/{print $2}' | head -n1 || true)"
        else
            x="$(curl -4 -fsS --retry 1 --connect-timeout 3 --max-time 6 "$u" 2>/dev/null || true)"
        fi
        x="$(trim "$x")"
        valid4 "$x" && { printf '%s\n' "$x"; return 0; }
    done
    printf '无\n'
}

get6() {
    local u x
    for u in \
        https://api6.ipify.org \
        https://ipv6.icanhazip.com \
        https://ifconfig.co/ip \
        https://1.1.1.1/cdn-cgi/trace
    do
        if [ "$u" = "https://1.1.1.1/cdn-cgi/trace" ]; then
            x="$(curl -6 -fsS --retry 1 --connect-timeout 3 --max-time 6 "$u" 2>/dev/null \
                | awk -F= '/^ip=/{print $2}' | head -n1 || true)"
        else
            x="$(curl -6 -fsS --retry 1 --connect-timeout 3 --max-time 6 "$u" 2>/dev/null || true)"
        fi
        x="$(trim "$x")"
        valid6 "$x" && { printf '%s\n' "$x"; return 0; }
    done
    printf '无\n'
}

get_count() {
    local n
    n="$(cat "$1" 2>/dev/null || echo 0)"
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    printf '%s\n' "$n"
}

debounce_no() {
    local fam="$1" raw="$2" old="$3" f n
    [ "$fam" = "4" ] && f="$NO4_FILE" || f="$NO6_FILE"

    if [ "$raw" != "无" ]; then
        printf '0\n' > "$f"
        printf '%s\n' "$raw"
        return
    fi

    if [ "$old" = "无" ]; then
        printf '0\n' > "$f"
        printf '无\n'
        return
    fi

    n="$(get_count "$f")"
    n=$((n+1))
    printf '%s\n' "$n" > "$f"
    [ "$n" -ge "$NO_THRESHOLD" ] && printf '无\n' || printf '%s\n' "$old"
}

html() {
    printf '%s' "$1" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'
}

tg_send() {
    local msg="$1" out rc
    [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ] || return 1

    out="$(curl -sS --retry 2 --retry-delay 1 --connect-timeout 5 --max-time 20 \
        -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${CHAT_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "disable_web_page_preview=true" \
        --data-urlencode "text=${msg}" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ] || ! printf '%s' "$out" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
        printf '%s\n' "$out" | head -c 2000 > "$TG_LAST_ERR" 2>/dev/null || true
        log ERROR "Telegram send failed: $out"
        return 1
    fi

    printf '%s\n' "$(bj_now)" > "$TG_LAST_OK"
    printf '%s\n' "$(epoch_now)" > "$TG_LAST_OK_EPOCH"
    rm -f "$TG_LAST_ERR" 2>/dev/null || true
    return 0
}

utf8_cp() {
    local cp="$1" b1 b2 b3 b4
    b1=$((240 | (cp >> 18)))
    b2=$((128 | ((cp >> 12) & 63)))
    b3=$((128 | ((cp >> 6) & 63)))
    b4=$((128 | (cp & 63)))
    printf "\\$(printf '%03o' "$b1")\\$(printf '%03o' "$b2")\\$(printf '%03o' "$b3")\\$(printf '%03o' "$b4")"
}

flag_from_cc() {
    local cc a b
    cc="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    [ "${#cc}" -eq 2 ] || { printf '🌐'; return; }
    a="$(printf '%d' "'${cc:0:1}" 2>/dev/null || echo 0)"
    b="$(printf '%d' "'${cc:1:1}" 2>/dev/null || echo 0)"
    [ "$a" -ge 65 ] && [ "$a" -le 90 ] && [ "$b" -ge 65 ] && [ "$b" -le 90 ] || {
        printf '🌐'; return;
    }
    utf8_cp $((127397+a)); utf8_cp $((127397+b))
}

clean_geo() {
    printf '%s' "$1" | tr '\r\n|' '   ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

json_string_field() {
    local json="$1" key="$2"
    printf '%s' "$json" | tr '\n' ' ' \
        | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

geo_info() {
    local ip="$1" cached json cc="" country="" region="" city="" flag loc
    [ "$GEO_ENABLE" = "1" ] || { printf '🌐|未查询\n'; return; }
    [ -n "$ip" ] && [ "$ip" != "无" ] || { printf '🌐|无\n'; return; }

    cached="$(grep -F "${ip}|" "$GEO_CACHE" 2>/dev/null | grep -v '|未知地区$' | tail -n1 || true)"
    [ -z "$cached" ] || { printf '%s\n' "${cached#*|}"; return; }

    json="$(curl -fsS --retry 1 --connect-timeout 4 --max-time 9 "https://ipwho.is/${ip}" 2>/dev/null || true)"
    if printf '%s' "$json" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true'; then
        cc="$(json_string_field "$json" country_code)"
        country="$(json_string_field "$json" country)"
        region="$(json_string_field "$json" region)"
        city="$(json_string_field "$json" city)"
    fi

    if [ -z "$cc" ]; then
        json="$(curl -fsS --retry 1 --connect-timeout 4 --max-time 9 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
        cc="$(json_string_field "$json" country)"
        region="$(json_string_field "$json" region)"
        city="$(json_string_field "$json" city)"
        printf '%s' "$cc" | grep -Eq '^[A-Za-z]{2}$' && country="$cc" || cc=""
    fi

    if [ -z "$cc" ]; then
        json="$(curl -fsS --retry 1 --connect-timeout 4 --max-time 9 "https://api.country.is/${ip}" 2>/dev/null || true)"
        cc="$(json_string_field "$json" country)"
        printf '%s' "$cc" | grep -Eq '^[A-Za-z]{2}$' && country="$cc" || cc=""
    fi

    cc="$(clean_geo "$cc")"
    country="$(clean_geo "$country")"
    region="$(clean_geo "$region")"
    city="$(clean_geo "$city")"

    printf '%s' "$cc" | grep -Eq '^[A-Za-z]{2}$' && flag="$(flag_from_cc "$cc")" || flag="🌐"

    loc="$country"
    if [ -n "$region" ] && [ "$region" != "$country" ]; then
        [ -n "$loc" ] && loc="$region, $loc" || loc="$region"
    fi
    if [ -n "$city" ] && [ "$city" != "$region" ] && [ "$city" != "$country" ]; then
        [ -n "$loc" ] && loc="$city, $loc" || loc="$city"
    fi

    [ -n "$loc" ] || { printf '🌐|未知地区\n'; return; }

    if [ -f "$GEO_CACHE" ]; then
        grep -Fv "${ip}|" "$GEO_CACHE" > "$GEO_CACHE.tmp.$$" 2>/dev/null || true
        mv "$GEO_CACHE.tmp.$$" "$GEO_CACHE" 2>/dev/null || true
    fi
    printf '%s|%s|%s\n' "$ip" "$flag" "$loc" >> "$GEO_CACHE"
    tail -n 300 "$GEO_CACHE" > "$GEO_CACHE.tmp.$$" 2>/dev/null \
        && mv "$GEO_CACHE.tmp.$$" "$GEO_CACHE" || true
    printf '%s|%s\n' "$flag" "$loc"
}

fmt_ip_geo() {
    local ip="$1" flag="$2" loc="$3"
    if [ "$ip" = "无" ]; then
        printf '<code>无</code>'
    else
        printf '%s <code>%s</code>' "$flag" "$(html "$ip")"
        [ -n "$loc" ] && [ "$loc" != "未知地区" ] && printf ' <code>%s</code>' "$(html "$loc")"
    fi
}

history_first() { head -n1 "$HISTORY" 2>/dev/null || true; }

history_write() {
    local tmp="$HISTORY.tmp.$$"
    {
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$@"
        head -n 9 "$HISTORY" 2>/dev/null || true
    } > "$tmp"
    mv "$tmp" "$HISTORY"
}

# ---------- Cloudflare, no jq ----------
cf_headers() {
    if [ "$CF_AUTH_MODE" = "global" ]; then
        printf 'X-Auth-Email: %s\n' "$CF_EMAIL"
        printf 'X-Auth-Key: %s\n' "$CF_API_KEY"
    else
        printf 'Authorization: Bearer %s\n' "$CF_API_TOKEN"
    fi
    printf 'Content-Type: application/json\n'
}

cf_request() {
    local method="$1" url="$2" data="${3:-}" line
    local -a args=()
    while IFS= read -r line; do
        [ -n "$line" ] && args+=(-H "$line")
    done < <(cf_headers)

    if [ -n "$data" ]; then
        curl -fsS --retry 1 --connect-timeout 5 --max-time 15 \
            -X "$method" "${args[@]}" --data "$data" "$url"
    else
        curl -fsS --retry 1 --connect-timeout 5 --max-time 15 \
            -X "$method" "${args[@]}" "$url"
    fi
}

cf_success() {
    printf '%s' "$1" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true'
}

cf_result0_id() {
    printf '%s' "$1" | tr -d '\n' \
        | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\[[[:space:]]*{[[:space:]]*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

cf_result0_content() {
    local x
    x="$(printf '%s' "$1" | tr -d '\n')"
    x="${x#*\"result\"}"
    printf '%s' "$x" \
        | sed -n 's/.*"content"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

cf_zone_id() {
    local zid resp
    zid="$(cat "$ZONE_CACHE" 2>/dev/null || true)"
    [ -z "$zid" ] || { printf '%s\n' "$zid"; return 0; }

    resp="$(cf_request GET "${CF_API_BASE}/zones?name=${CF_ZONE_NAME}&status=active&per_page=1" 2>/dev/null)" || return 1
    cf_success "$resp" || return 1
    zid="$(cf_result0_id "$resp")"
    [ -n "$zid" ] || return 1
    printf '%s\n' "$zid" > "$ZONE_CACHE"
    printf '%s\n' "$zid"
}

cf_record_info() {
    local zid="$1" type="$2" resp id content
    resp="$(cf_request GET "${CF_API_BASE}/zones/${zid}/dns_records?type=${type}&name=${CF_RECORD_NAME}&per_page=1" 2>/dev/null)" || return 1
    cf_success "$resp" || return 1
    id="$(cf_result0_id "$resp")"
    content="$(cf_result0_content "$resp")"
    printf '%s\t%s\n' "$id" "$content"
}

cf_payload() {
    local type="$1" ip="$2"
    printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s}' \
        "$type" "$CF_RECORD_NAME" "$ip" "$CF_TTL" \
        "$([ "$CF_PROXIED" = "true" ] && echo true || echo false)"
}

cf_create() {
    local zid="$1" type="$2" ip="$3" resp
    resp="$(cf_request POST "${CF_API_BASE}/zones/${zid}/dns_records" "$(cf_payload "$type" "$ip")" 2>/dev/null)" || return 1
    cf_success "$resp"
}

cf_update() {
    local zid="$1" rid="$2" type="$3" ip="$4" resp
    resp="$(cf_request PUT "${CF_API_BASE}/zones/${zid}/dns_records/${rid}" "$(cf_payload "$type" "$ip")" 2>/dev/null)" || return 1
    cf_success "$resp"
}

CF4_STATUS="未执行"
CF6_STATUS="未执行"
RECOVERY_MSG=""
NEW_CF_FAILURE=""
CF_RETRY_SECONDS=300
CF_AUDIT_SECONDS=1800

mark_cf_failure() {
    local type="$1" f="$2"
    [ -f "$f" ] || NEW_CF_FAILURE="${NEW_CF_FAILURE}${type} "
    touch "$f"
}

cf_due() {
    local now last wait
    now="$(epoch_now)"
    last="$(cat "$LAST_CF_ATTEMPT" 2>/dev/null || echo 0)"
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    if [ -f "$CF4_FAIL" ] || [ -f "$CF6_FAIL" ]; then wait="$CF_RETRY_SECONDS"; else wait="$CF_AUDIT_SECONDS"; fi
    [ $((now-last)) -ge "$wait" ]
}

cf_reconcile_one() {
    local fam="$1" type="$2" ip="$3" failfile zid info rid old status
    [ "$fam" = "4" ] && failfile="$CF4_FAIL" || failfile="$CF6_FAIL"

    if [ "$ip" = "无" ] || [ -z "$ip" ]; then
        status="跳过（无有效 IP）"
        [ "$fam" = "4" ] && CF4_STATUS="$status" || CF6_STATUS="$status"
        return
    fi

    zid="$(cf_zone_id)" || {
        status="失败（Zone/API）"
        mark_cf_failure "$type" "$failfile"
        rm -f "$ZONE_CACHE"
        [ "$fam" = "4" ] && CF4_STATUS="$status" || CF6_STATUS="$status"
        return 1
    }

    info="$(cf_record_info "$zid" "$type")" || {
        status="失败（查询记录）"
        mark_cf_failure "$type" "$failfile"
        [ "$fam" = "4" ] && CF4_STATUS="$status" || CF6_STATUS="$status"
        return 1
    }

    rid="${info%%$'\t'*}"
    old="${info#*$'\t'}"

    if [ -z "$rid" ]; then
        if cf_create "$zid" "$type" "$ip"; then
            status="已创建"
        else
            status="失败（创建）"
            mark_cf_failure "$type" "$failfile"
        fi
    elif [ "$old" = "$ip" ]; then
        status="已同步"
    else
        if cf_update "$zid" "$rid" "$type" "$ip"; then
            status="已更新"
        else
            status="失败（更新）"
            mark_cf_failure "$type" "$failfile"
        fi
    fi

    if [ "$status" = "已创建" ] || [ "$status" = "已同步" ] || [ "$status" = "已更新" ]; then
        if [ -f "$failfile" ]; then
            rm -f "$failfile"
            RECOVERY_MSG="${RECOVERY_MSG}${type} "
        fi
    fi

    [ "$fam" = "4" ] && CF4_STATUS="$status" || CF6_STATUS="$status"
}

cf_reconcile_all() {
    [ "$MODE" = "ddns" ] || return
    NEW_CF_FAILURE=""; RECOVERY_MSG=""
    [ "$ENABLE_IPV4" = "1" ] && cf_reconcile_one 4 A "$1" || true
    [ "$ENABLE_IPV6" = "1" ] && cf_reconcile_one 6 AAAA "$2" || true
    printf '%s\n' "$(epoch_now)" > "$LAST_CF_ATTEMPT"
}

send_cf_failure_if_needed() {
    [ -n "$NEW_CF_FAILURE" ] || return
    tg_send "⚠️ <b>Cloudflare DDNS 同步异常</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>
<b>记录:</b> <code>$(html "$CF_RECORD_NAME")</code>
<b>异常:</b> <code>$(html "$NEW_CF_FAILURE")</code>
<b>A:</b> <code>$(html "$CF4_STATUS")</code>
<b>AAAA:</b> <code>$(html "$CF6_STATUS")</code>
<b>策略:</b> <code>约5分钟后自动重试</code>
<b>北京时间:</b> <code>$(bj_now)</code>" || true
}

send_cf_recovery_if_needed() {
    [ -n "$RECOVERY_MSG" ] || return
    tg_send "✅ <b>DDNS 同步已恢复</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>
<b>记录:</b> <code>$(html "$CF_RECORD_NAME")</code>
<b>恢复:</b> <code>$(html "$RECOVERY_MSG")</code>
<b>北京时间:</b> <code>$(bj_now)</code>" || true
}

check_once() {
    local raw4="无" raw6="无" cur4 cur6 now epoch first
    local old_epoch old_time old4 old6 oldf4 oldl4 oldf6 oldl6
    local changed4=0 changed6=0 verify
    local g4 f4 l4 g6 f6 l6 og4 of4 ol4 og6 of6 ol6 msg

    mkdir "$LOCKDIR" 2>/dev/null || return 0
    trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT INT TERM

    now="$(bj_now)"
    epoch="$(epoch_now)"
    printf '%s\n' "$now" > "$LAST_CHECK"
    printf '%s\n' "$epoch" > "$LAST_CHECK_EPOCH"

    [ "$ENABLE_IPV4" = "1" ] && raw4="$(get4)"
    [ "$ENABLE_IPV6" = "1" ] && raw6="$(get6)"

    first="$(history_first)"
    if [ -z "$first" ]; then
        if { [ "$ENABLE_IPV4" != "1" ] || [ "$raw4" = "无" ]; } \
           && { [ "$ENABLE_IPV6" != "1" ] || [ "$raw6" = "无" ]; }; then
            log WARN "Initial check: no valid IP"
            return 0
        fi

        g4="$(geo_info "$raw4")"; f4="${g4%%|*}"; l4="${g4#*|}"
        g6="$(geo_info "$raw6")"; f6="${g6%%|*}"; l6="${g6#*|}"
        history_write "$epoch" "$now" "$raw4" "$raw6" "$f4" "$l4" "$f6" "$l6"
        printf '0\n' > "$NO4_FILE"; printf '0\n' > "$NO6_FILE"
        cf_reconcile_all "$raw4" "$raw6"
        send_cf_failure_if_needed
        printf '%s\n' "$now" > "$LAST_OK"
        log INFO "Baseline initialized IPv4=$raw4 IPv6=$raw6"
        return 0
    fi

    old_epoch="$(printf '%s' "$first" | awk -F'|' '{print $1}')"
    old_time="$(printf '%s' "$first" | awk -F'|' '{print $2}')"
    old4="$(printf '%s' "$first" | awk -F'|' '{print $3}')"
    old6="$(printf '%s' "$first" | awk -F'|' '{print $4}')"
    oldf4="$(printf '%s' "$first" | awk -F'|' '{print $5}')"
    oldl4="$(printf '%s' "$first" | awk -F'|' '{print $6}')"
    oldf6="$(printf '%s' "$first" | awk -F'|' '{print $7}')"
    oldl6="$(printf '%s' "$first" | awk -F'|' '{print $8}')"
    [ -n "$old4" ] || old4="无"; [ -n "$old6" ] || old6="无"

    cur4="$old4"; cur6="$old6"
    [ "$ENABLE_IPV4" = "1" ] && cur4="$(debounce_no 4 "$raw4" "$old4")"
    [ "$ENABLE_IPV6" = "1" ] && cur6="$(debounce_no 6 "$raw6" "$old6")"
    [ "$cur4" != "$old4" ] && changed4=1
    [ "$cur6" != "$old6" ] && changed6=1

    if [ "$changed4" -eq 1 ] || [ "$changed6" -eq 1 ]; then
        sleep 2
        if [ "$changed4" -eq 1 ]; then
            verify="$(get4)"
            [ "$verify" = "$cur4" ] || { changed4=0; cur4="$old4"; }
        fi
        if [ "$changed6" -eq 1 ]; then
            verify="$(get6)"
            [ "$verify" = "$cur6" ] || { changed6=0; cur6="$old6"; }
        fi
    fi

    if [ "$MODE" = "ddns" ]; then
        if [ "$changed4" -eq 1 ] || [ "$changed6" -eq 1 ] || cf_due; then
            cf_reconcile_all "$cur4" "$cur6"
        else
            CF4_STATUS="未检查（无需同步）"; CF6_STATUS="未检查（无需同步）"
            NEW_CF_FAILURE=""; RECOVERY_MSG=""
        fi
    fi

    if [ "$changed4" -eq 0 ] && [ "$changed6" -eq 0 ]; then
        send_cf_failure_if_needed
        send_cf_recovery_if_needed
        printf '%s\n' "$now" > "$LAST_OK"
        return 0
    fi

    og4="$(geo_info "$old4")"; of4="${og4%%|*}"; ol4="${og4#*|}"
    og6="$(geo_info "$old6")"; of6="${og6%%|*}"; ol6="${og6#*|}"
    g4="$(geo_info "$cur4")"; f4="${g4%%|*}"; l4="${g4#*|}"
    g6="$(geo_info "$cur6")"; f6="${g6%%|*}"; l6="${g6#*|}"

    history_write "$epoch" "$now" "$cur4" "$cur6" "$f4" "$l4" "$f6" "$l6"

    msg="🚨 <b>VPS IP 变化通知</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>
<b>旧 IPv4:</b> $(fmt_ip_geo "$old4" "$of4" "$ol4")
<b>新 IPv4:</b> $(fmt_ip_geo "$cur4" "$f4" "$l4")
<b>旧 IPv6:</b> $(fmt_ip_geo "$old6" "$of6" "$ol6")
<b>新 IPv6:</b> $(fmt_ip_geo "$cur6" "$f6" "$l6")
<b>北京时间:</b> <code>$now</code>"

    if [ "$MODE" = "ddns" ]; then
        msg="${msg}

<b>Cloudflare DDNS:</b>
A: <code>$(html "$CF4_STATUS")</code>
AAAA: <code>$(html "$CF6_STATUS")</code>
记录: <code>$(html "$CF_RECORD_NAME")</code>"
    fi

    tg_send "$msg" || true
    printf '%s\n' "$now" > "$LAST_OK"
    log INFO "IP changed $old4/$old6 -> $cur4/$cur6"
}

service_status() {
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipchange.service ]; then
        systemctl is-active ipchange 2>/dev/null || true
        return
    fi
    if command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/ipchange ]; then
        rc-service ipchange status 2>/dev/null | head -n1 || true
        return
    fi
    if [ -f "$PIDFILE" ]; then
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { echo "running (PID $pid)"; return; }
    fi
    echo "stopped/unknown"
}

service_active() {
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipchange.service ]; then
        systemctl is-active --quiet ipchange 2>/dev/null
        return
    fi
    if command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/ipchange ]; then
        rc-service ipchange status >/dev/null 2>&1
        return
    fi
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

service_enabled() {
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipchange.service ]; then
        systemctl is-enabled --quiet ipchange 2>/dev/null
        return
    fi
    if command -v rc-update >/dev/null 2>&1 && [ -f /etc/init.d/ipchange ]; then
        rc-update show default 2>/dev/null | grep -Eq '(^|[[:space:]])ipchange([[:space:]]|$)'
        return
    fi
    return 1
}

timing_values() {
    TIMING_NOW="$(epoch_now)"
    TIMING_LAST="$(cat "$LAST_CHECK_EPOCH" 2>/dev/null || echo 0)"
    TIMING_NEXT="$(cat "$NEXT_CHECK_EPOCH" 2>/dev/null || echo 0)"
    case "$TIMING_LAST" in ''|*[!0-9]*) TIMING_LAST=0 ;; esac
    case "$TIMING_NEXT" in ''|*[!0-9]*) TIMING_NEXT=0 ;; esac

    if [ "$TIMING_LAST" -gt 0 ]; then
        TIMING_AGE=$((TIMING_NOW - TIMING_LAST))
        [ "$TIMING_AGE" -lt 0 ] && TIMING_AGE=0
    else
        TIMING_AGE=-1
    fi

    if [ "$TIMING_NEXT" -gt 0 ]; then
        TIMING_LEFT=$((TIMING_NEXT - TIMING_NOW))
    else
        TIMING_LEFT=-1
    fi
}

heartbeat_state() {
    timing_values
    if ! service_active; then
        printf '❌ 服务未运行'
        return
    fi
    if [ "$TIMING_AGE" -lt 0 ]; then
        printf '⚠️ 服务运行中，但尚无检测心跳'
        return
    fi
    if [ "$TIMING_AGE" -gt $((INTERVAL*60+180)) ]; then
        printf '❌ 心跳过旧，后台可能异常'
        return
    fi
    printf '✅ 后台定时执行正常'
}

status_core() {
    local first i4="无" i6="无"
    first="$(history_first)"
    if [ -n "$first" ]; then
        i4="$(printf '%s' "$first" | awk -F'|' '{print $3}')"
        i6="$(printf '%s' "$first" | awk -F'|' '{print $4}')"
    fi

    timing_values

    echo "=================================================="
    echo " ipchange Enterprise v$VERSION"
    echo "=================================================="
    echo "VPS          : $VPS_NAME"
    echo "模式         : $([ "$MODE" = "ddns" ] && echo 'DDNS + 通知' || echo '仅通知')"
    echo "监控         : IPv4=$ENABLE_IPV4  IPv6=$ENABLE_IPV6"
    echo "检测间隔     : ${INTERVAL} 分钟"
    echo "后台状态     : $(heartbeat_state)"
    echo "服务状态     : $(service_status | head -n1)"
    echo "开机自启     : $(service_enabled && echo '✅ 已启用' || echo '⚠️ 未确认')"
    echo "当前 IPv4    : ${i4:-无}"
    echo "当前 IPv6    : ${i6:-无}"
    echo "最近检查     : $(cat "$LAST_CHECK" 2>/dev/null || echo 尚无)"

    timing_values
    if [ "$TIMING_AGE" -ge 0 ]; then
        echo "距上次检查   : $(human_seconds "$TIMING_AGE") 前"
    else
        echo "距上次检查   : 未知"
    fi

    if [ "$TIMING_NEXT" -gt 0 ]; then
        echo "预计下次检查 : $(epoch_to_bj "$TIMING_NEXT")"
        if [ "$TIMING_LEFT" -gt 0 ]; then
            echo "距离下次检查 : $(human_seconds "$TIMING_LEFT")"
        else
            echo "距离下次检查 : 即将执行 / 正在执行"
        fi
    else
        echo "预计下次检查 : 尚未计算"
        echo "距离下次检查 : 尚未计算"
    fi

    echo "最近成功     : $(cat "$LAST_OK" 2>/dev/null || echo 尚无)"
    echo "TG最近成功   : $(cat "$TG_LAST_OK" 2>/dev/null || echo 尚无)"
    echo "IPv4无计数  : $(get_count "$NO4_FILE")/$NO_THRESHOLD"
    echo "IPv6无计数  : $(get_count "$NO6_FILE")/$NO_THRESHOLD"
    if [ "$CLEANUP_DAYS" -eq 0 ]; then
        echo "自动清理     : 已关闭"
    else
        echo "日志/缓存保留: ${CLEANUP_DAYS} 天"
        echo "最近自动清理 : $(cat "$CLEANUP_LAST" 2>/dev/null || echo 尚无)"
    fi

    if [ "$MODE" = "ddns" ]; then
        echo "CF Zone      : $CF_ZONE_NAME"
        echo "CF Record    : $CF_RECORD_NAME"
        echo "A失败状态    : $([ -f "$CF4_FAIL" ] && echo '⚠️ 待恢复' || echo '✅ 正常')"
        echo "AAAA失败状态 : $([ -f "$CF6_FAIL" ] && echo '⚠️ 待恢复' || echo '✅ 正常')"
    fi
    echo "北京时间     : $(bj_now)"
}

status() { status_core; }

monitor() {
    local refresh="${1:-2}"
    case "$refresh" in ''|*[!0-9]*) refresh=2 ;; esac
    [ "$refresh" -lt 1 ] && refresh=1
    [ "$refresh" -gt 60 ] && refresh=60

    if [ ! -t 1 ]; then
        echo "当前不是交互终端，改为显示一次 status。"
        status_core
        return
    fi

    trap 'printf "\n已退出 ipchange monitor。\n"; exit 0' INT TERM
    while :; do
        printf '\033[H\033[2J'
        echo "ipchange monitor  |  每 ${refresh} 秒刷新  |  Ctrl+C 退出"
        echo
        status_core
        echo
        echo "提示：monitor 只观察状态，不会主动触发 IP/DDNS 检测。"
        sleep "$refresh"
    done
}

telegram_api_post() {
    local method="$1"; shift
    local out
    out="$(curl -sS --retry 2 --retry-delay 1 --connect-timeout 5 --max-time 18 \
        -X POST "https://api.telegram.org/bot${BOT_TOKEN}/${method}" "$@" 2>&1)"
    if printf '%s' "$out" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
        return 0
    fi
    printf '%s\n' "$out" | head -c 2000 > "$TG_LAST_ERR" 2>/dev/null || true
    return 1
}

telegram_api_test() {
    [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ] || return 1
    telegram_api_post getChat --data-urlencode "chat_id=${CHAT_ID}" && return 0
    telegram_api_post sendChatAction --data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "action=typing" && return 0
    telegram_api_post getMe && return 0

    local last now
    last="$(cat "$TG_LAST_OK_EPOCH" 2>/dev/null || echo 0)"
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    now="$(epoch_now)"
    [ "$last" -gt 0 ] && [ $((now-last)) -le 86400 ]
}

test_notify() {
    local i4="无" i6="无" g4 f4 l4 g6 f6 l6
    [ "$ENABLE_IPV4" = "1" ] && i4="$(get4)"
    [ "$ENABLE_IPV6" = "1" ] && i6="$(get6)"
    g4="$(geo_info "$i4")"; f4="${g4%%|*}"; l4="${g4#*|}"
    g6="$(geo_info "$i6")"; f6="${g6%%|*}"; l6="${g6#*|}"

    [ "$MODE" = "ddns" ] && cf_reconcile_all "$i4" "$i6"

    local msg="🧪 <b>ipchange 测试通知</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>
<b>模式:</b> <code>$([ "$MODE" = "ddns" ] && echo 'DDNS + 通知' || echo '仅通知')</code>
<b>IPv4:</b> $(fmt_ip_geo "$i4" "$f4" "$l4")
<b>IPv6:</b> $(fmt_ip_geo "$i6" "$f6" "$l6")
<b>北京时间:</b> <code>$(bj_now)</code>
<b>无结果策略:</b> <code>连续 ${NO_THRESHOLD} 次才确认</code>"

    if [ "$MODE" = "ddns" ]; then
        msg="${msg}
<b>DDNS A:</b> <code>$(html "$CF4_STATUS")</code>
<b>DDNS AAAA:</b> <code>$(html "$CF6_STATUS")</code>"
    fi

    echo "正在发送 Telegram 测试通知..."
    tg_send "$msg" && echo "✅ Telegram 测试成功。" || {
        echo "❌ Telegram 测试失败，请执行 ipchange logs"
        return 1
    }
}

geo_test_one() {
    local label="$1" ip="$2" g loc
    echo "----------------------------------------------"
    echo "$label"
    echo "IP   : $ip"
    [ -n "$ip" ] && [ "$ip" != "无" ] || { echo "⚠️ 当前没有有效 $label 地址。"; return 2; }

    if [ -f "$GEO_CACHE" ]; then
        grep -Fv "${ip}|" "$GEO_CACHE" > "$GEO_CACHE.tmp.$$" 2>/dev/null || true
        mv "$GEO_CACHE.tmp.$$" "$GEO_CACHE" 2>/dev/null || true
    fi

    g="$(geo_info "$ip")"; loc="${g#*|}"
    echo "旗帜 : ${g%%|*}"
    echo "地区 : $loc"
    [ "$loc" = "未知地区" ] && { echo "⚠️ 地区查询源暂不可用。"; return 1; }
    echo "✅ $label 地区查询成功。"
}

geo_test() {
    local ip="${1:-}" i4="无" i6="无" rc=0
    echo "=================================================="
    echo " ipchange IPv4 / IPv6 地区与旗帜测试"
    echo "=================================================="

    if [ -n "$ip" ]; then
        valid4 "$ip" && { geo_test_one IPv4 "$ip"; return $?; }
        valid6 "$ip" && { geo_test_one IPv6 "$ip"; return $?; }
        echo "❌ 无效 IP：$ip"; return 1
    fi

    if [ "$ENABLE_IPV4" = "1" ]; then
        i4="$(get4)"
        geo_test_one IPv4 "$i4" || [ $? -eq 2 ] || rc=1
    fi
    if [ "$ENABLE_IPV6" = "1" ]; then
        i6="$(get6)"
        geo_test_one IPv6 "$i6" || [ $? -eq 2 ] || rc=1
    fi
    return "$rc"
}

cloudflare_test() {
    [ "$MODE" = "ddns" ] || { echo "当前为仅通知模式，Cloudflare 检查跳过。"; return 0; }
    local zid info rid remote i4="无" i6="无" bad=0

    rm -f "$ZONE_CACHE"
    zid="$(cf_zone_id 2>/dev/null || true)"
    [ -n "$zid" ] || { echo "❌ Cloudflare API/Zone 验证失败"; return 1; }
    echo "✅ Cloudflare API / Zone 正常"

    [ "$ENABLE_IPV4" = "1" ] && i4="$(get4)"
    [ "$ENABLE_IPV6" = "1" ] && i6="$(get6)"

    if [ "$ENABLE_IPV4" = "1" ]; then
        info="$(cf_record_info "$zid" A 2>/dev/null || true)"
        rid="${info%%$'\t'*}"; remote="${info#*$'\t'}"
        echo "A 本机/CF    : $i4 / ${remote:-无}"
        [ -n "$rid" ] && [ "$i4" != "无" ] && [ "$remote" = "$i4" ] \
            && echo "✅ A 记录一致" || { echo "❌ A 记录异常/不一致"; bad=1; }
    fi

    if [ "$ENABLE_IPV6" = "1" ]; then
        info="$(cf_record_info "$zid" AAAA 2>/dev/null || true)"
        rid="${info%%$'\t'*}"; remote="${info#*$'\t'}"
        echo "AAAA本机/CF : $i6 / ${remote:-无}"
        if [ "$i6" = "无" ]; then
            echo "⚠️ 当前无 IPv6，AAAA 无法比较"
        elif [ -n "$rid" ] && [ "$remote" = "$i6" ]; then
            echo "✅ AAAA 记录一致"
        else
            echo "❌ AAAA 记录异常/不一致"; bad=1
        fi
    fi

    return "$bad"
}

service_test() {
    echo "=================================================="
    echo " ipchange 服务 / 定时心跳检查"
    echo "=================================================="
    status_core
    echo
    service_active && echo "✅ 守护服务运行中" || echo "❌ 守护服务未运行"
    service_enabled && echo "✅ 开机自启已启用" || echo "⚠️ 未确认开机自启"

    timing_values
    if [ "$TIMING_AGE" -ge 0 ] && [ "$TIMING_AGE" -le $((INTERVAL*60+180)) ]; then
        echo "✅ 最近心跳时间正常"
        return 0
    fi
    echo "❌ 最近心跳异常/过旧"
    return 1
}

doctor() {
    local ok=0 warn=0 bad=0 i4="disabled" i6="disabled" g

    echo "=================================================="
    echo " ipchange Enterprise v$VERSION 综合自检"
    echo "=================================================="

    echo "[1/8] 程序与目录"
    if [ -x /usr/local/bin/ipchange ] && bash -n /usr/local/bin/ipchange >/dev/null 2>&1; then
        echo "✅ 主程序正常"; ok=$((ok+1))
    else
        echo "❌ 主程序异常"; bad=$((bad+1))
    fi
    [ -r "$CONF" ] && { echo "✅ 配置正常"; ok=$((ok+1)); } || { echo "❌ 配置异常"; bad=$((bad+1)); }

    echo
    echo "[2/8] 依赖"
    command -v curl >/dev/null 2>&1 && { echo "✅ curl 正常"; ok=$((ok+1)); } || { echo "❌ curl 缺失"; bad=$((bad+1)); }
    echo "✅ Cloudflare JSON 模块不依赖 jq"; ok=$((ok+1))

    echo
    echo "[3/8] 后台服务与心跳"
    if service_active; then echo "✅ 服务运行中"; ok=$((ok+1)); else echo "❌ 服务未运行"; bad=$((bad+1)); fi
    if service_enabled; then echo "✅ 开机自启"; ok=$((ok+1)); else echo "⚠️ 未确认开机自启"; warn=$((warn+1)); fi
    echo "状态：$(heartbeat_state)"
    timing_values
    if [ "$TIMING_AGE" -ge 0 ] && [ "$TIMING_AGE" -le $((INTERVAL*60+180)) ]; then
        echo "✅ 心跳正常，$(human_seconds "$TIMING_AGE") 前执行"; ok=$((ok+1))
    else
        echo "❌ 心跳异常"; bad=$((bad+1))
    fi
    [ "$TIMING_NEXT" -gt 0 ] && echo "ℹ️ 预计下次：$(epoch_to_bj "$TIMING_NEXT")"

    echo
    echo "[4/8] 公网 IPv4 / IPv6"
    if [ "$ENABLE_IPV4" = "1" ]; then
        i4="$(get4)"
        [ "$i4" != "无" ] && { echo "✅ IPv4：$i4"; ok=$((ok+1)); } || { echo "❌ IPv4 获取失败"; bad=$((bad+1)); }
    fi
    if [ "$ENABLE_IPV6" = "1" ]; then
        i6="$(get6)"
        [ "$i6" != "无" ] && { echo "✅ IPv6：$i6"; ok=$((ok+1)); } || { echo "⚠️ IPv6 当前无结果"; warn=$((warn+1)); }
    fi

    echo
    echo "[5/8] Telegram"
    if telegram_api_test; then
        echo "✅ Telegram API / Bot / Chat ID 链路正常"; ok=$((ok+1))
        [ -f "$TG_LAST_OK" ] && echo "   最近实际发送：$(cat "$TG_LAST_OK")"
    else
        echo "⚠️ Telegram 辅助探测失败，请以 ipchange test 实际收信为准"; warn=$((warn+1))
    fi

    echo
    echo "[6/8] IPv4 / IPv6 地区"
    if [ "$ENABLE_IPV4" = "1" ] && [ "$i4" != "无" ] && [ "$i4" != "disabled" ]; then
        g="$(geo_info "$i4")"
        [ "${g#*|}" = "未知地区" ] && { echo "⚠️ IPv4 地区暂不可用"; warn=$((warn+1)); } \
                                      || { echo "✅ IPv4 地区：${g%%|*} ${g#*|}"; ok=$((ok+1)); }
    fi
    if [ "$ENABLE_IPV6" = "1" ] && [ "$i6" != "无" ] && [ "$i6" != "disabled" ]; then
        g="$(geo_info "$i6")"
        [ "${g#*|}" = "未知地区" ] && { echo "⚠️ IPv6 地区暂不可用"; warn=$((warn+1)); } \
                                      || { echo "✅ IPv6 地区：${g%%|*} ${g#*|}"; ok=$((ok+1)); }
    fi

    echo
    echo "[7/8] Cloudflare DDNS"
    if [ "$MODE" = "ddns" ]; then
        if cloudflare_test; then ok=$((ok+1)); else bad=$((bad+1)); fi
    else
        echo "✅ 仅通知模式，无需 Cloudflare"; ok=$((ok+1))
    fi

    echo
    echo "[8/8] 日志 / 自动清理"
    local errors
    errors="$(tail -n 200 "$LOG_FILE" 2>/dev/null | grep -c '\[ERROR\]' || true)"
    case "$errors" in ''|*[!0-9]*) errors=0 ;; esac
    [ "$errors" -eq 0 ] && { echo "✅ 最近日志无 ERROR"; ok=$((ok+1)); } \
                         || { echo "⚠️ 最近日志有 $errors 条 ERROR"; warn=$((warn+1)); }
    if [ "$CLEANUP_DAYS" -eq 0 ]; then
        echo "⚠️ 自动清理已关闭"; warn=$((warn+1))
    else
        echo "✅ 日志/缓存保留策略：${CLEANUP_DAYS} 天"; ok=$((ok+1))
        echo "   最近清理：$(cat "$CLEANUP_LAST" 2>/dev/null || echo 尚无)"
    fi

    echo
    echo "=================================================="
    echo "自检结果：✅ ${ok} 项通过  ⚠️ ${warn} 项警告  ❌ ${bad} 项失败"
    [ "$bad" -eq 0 ] && { echo "✅ 核心自检通过"; return 0; }
    echo "❌ 自检发现核心问题"
    return 1
}

manual_check() {
    echo "正在执行一次立即检查..."
    check_once
    status_core
}

daemon_loop() {
    echo "$$" > "$PIDFILE"
    trap 'rm -f "$PIDFILE" "$NEXT_CHECK_EPOCH"; exit 0' INT TERM EXIT
    log INFO "daemon started interval=${INTERVAL}m mode=$MODE"

    while :; do
        auto_cleanup_if_due || log WARN "auto cleanup returned error"
        ( check_once ) || log ERROR "check_once returned error"

        # Schedule from the end of this cycle. This is the source of truth for
        # `ipchange status` and `ipchange monitor`.
        local next
        next=$(( $(epoch_now) + INTERVAL*60 ))
        printf '%s\n' "$next" > "$NEXT_CHECK_EPOCH"
        sleep "$((INTERVAL*60))"
    done
}

restart_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipchange.service ]; then
        systemctl restart ipchange
        systemctl --no-pager --full status ipchange 2>/dev/null | head -n12 || true
        return
    fi
    if command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/ipchange ]; then
        rc-service ipchange restart
        rc-service ipchange status || true
        return
    fi
    echo "未检测到 systemd/OpenRC 服务。"
    return 1
}

show_logs() {
    [ -s "$LOG_FILE" ] && tail -n 100 "$LOG_FILE" || echo "暂无当前运行日志。"
    echo
    echo "日志目录：$LOG_DIR"
    echo "保留策略：$([ "$CLEANUP_DAYS" -eq 0 ] && echo '关闭自动清理' || echo "${CLEANUP_DAYS} 天")"
}

setup_again() {
    [ -f "$SETUP" ] && exec bash "$SETUP"
    echo "找不到安装器副本：$SETUP"
    return 1
}

usage() {
cat <<EOF
ipchange Enterprise v$VERSION

命令：
  ipchange status          查看一次状态（含上次/下次检测时间）
  ipchange monitor [秒]    实时状态面板，默认每2秒刷新
  ipchange doctor          企业级综合自检
  ipchange service-test    检查守护服务/开机自启/定时心跳
  ipchange check           立即手动检查一次
  ipchange test            Telegram 实际收信测试
  ipchange cf-test         Cloudflare API 与 A/AAAA 检查
  ipchange geotest [IP]    地区/旗帜测试；不填时分别检查 v4/v6
  ipchange restart         重启后台服务
  ipchange repair          重启服务后自动 doctor
  ipchange logs            查看最近日志
  ipchange cleanup         立即执行一次日志/缓存清理
  ipchange setup           重新配置（可修改保留天数）
  ipchange version         查看版本
EOF
}

case "${1:-status}" in
    version) echo "ipchange Enterprise v$VERSION" ;;
    status) status ;;
    monitor) monitor "${2:-2}" ;;
    doctor|diag|diagnose) doctor ;;
    service-test) service_test ;;
    check) manual_check ;;
    test) test_notify ;;
    cf-test) cloudflare_test ;;
    geotest) geo_test "${2:-}" ;;
    restart) restart_service ;;
    repair) restart_service; sleep 2; doctor ;;
    logs) show_logs ;;
    cleanup) cleanup_storage 0 ;;
    setup) setup_again ;;
    daemon) daemon_loop ;;
    -h|--help|help) usage ;;
    *) usage; exit 1 ;;
esac
EOS
    chmod 755 "$BIN"
}

stop_known_pidfile() {
    local pf="$1" pid cmd=""
    [ -f "$pf" ] || return 0
    pid="$(cat "$pf" 2>/dev/null || true)"
    case "$pid" in ''|*[!0-9]*) rm -f "$pf"; return 0 ;; esac
    if [ "$pid" = "$$" ] || [ "$pid" = "$PPID" ]; then
        rm -f "$pf"
        return 0
    fi

    if kill -0 "$pid" 2>/dev/null; then
        [ -r "/proc/$pid/cmdline" ] && cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
        case "$cmd" in
            *ipchange*daemon*)
                kill "$pid" 2>/dev/null || true
                sleep 1
                kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
                ;;
        esac
    fi
    rm -f "$pf"
}

install_service() {
    say "正在安全清理旧版守护方式..."

    have systemctl && [ -d /run/systemd/system ] && systemctl stop ipchange >/dev/null 2>&1 || true
    if have rc-service; then
        [ -f "$OPENRC_SERVICE" ] && rc-service ipchange stop >/dev/null 2>&1 || true
        [ -f /etc/init.d/ipchange-watch ] && rc-service ipchange-watch stop >/dev/null 2>&1 || true
    fi

    stop_known_pidfile "$STATE_DIR/daemon.pid"
    rm -f "$STATE_DIR/next_check_epoch" /etc/cron.d/ipchange 2>/dev/null || true

    if have systemctl && [ -d /run/systemd/system ]; then
        cat > "$SYSTEMD_UNIT" <<'EOF'
[Unit]
Description=ipchange Enterprise IP Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ipchange daemon
Restart=always
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
EOF
        run_with_progress "加载 systemd 服务" systemctl daemon-reload
        run_with_progress "启用并启动 ipchange" systemctl enable --now ipchange
        say "✅ systemd 守护服务已启用。"
        return
    fi

    if have rc-update && have rc-service && [ -x /sbin/openrc-run ]; then
        cat > "$OPENRC_SERVICE" <<'EOF'
#!/sbin/openrc-run
name="ipchange Enterprise"
description="VPS IP monitor with Telegram and optional Cloudflare DDNS"

command="/usr/local/bin/ipchange"
command_args="daemon"
command_background="yes"
pidfile="/run/ipchange.pid"
output_log="/root/ipchange/logs/openrc.log"
error_log="/root/ipchange/logs/openrc.log"

depend() {
    need net
    after firewall
}
EOF
        chmod 755 "$OPENRC_SERVICE"
        run_with_progress "注册 OpenRC 自启动" rc-update add ipchange default || true
        run_with_progress "启动 ipchange OpenRC 服务" rc-service ipchange restart
        say "✅ OpenRC 守护服务已启用。"
        return
    fi

    say "⚠️ 未检测到 systemd/OpenRC，使用临时 nohup。"
    nohup "$BIN" daemon >> "$LOG_DIR/nohup.log" 2>&1 &
    sleep 1
    kill -0 "$!" 2>/dev/null
}

verify_install() {
    bash -n "$BIN"
    [ "$("$BIN" version)" = "ipchange Enterprise v$VERSION" ]
}

main() {
    local warn=0 testnow=""

    need_root

    stage 1 10 "初始化 /root/ipchange"
    mkdirs
    migrate_layout

    stage 2 10 "检查基础依赖"
    install_deps

    stage 3 10 "读取已有配置"
    load_defaults

    [ -f "$0" ] && cp -f "$0" "$SETUP_COPY" 2>/dev/null || true
    chmod 700 "$SETUP_COPY" 2>/dev/null || true

    stage 4 10 "交互配置"
    write_config

    stage 5 10 "安装主程序"
    install_program
    verify_install
    say "✅ 主程序语法与版本检查通过。"

    stage 6 10 "配置后台服务与开机自启"
    install_service || warn=1

    stage 7 10 "验证后台状态"
    sleep 2
    "$BIN" service-test || warn=1

    stage 8 10 "首次检测 / 建立基线"
    run_with_progress "首次 IP / DDNS 检测" "$BIN" check || warn=1

    stage 9 10 "综合自检"
    "$BIN" doctor || warn=1

    stage 10 10 "可选 Telegram 实际收信测试"
    tty_printf "是否立即发送 Telegram 测试通知？[Y/n]: "
    read_tty testnow
    case "$testnow" in
        n|N|no|NO) say "ℹ️ 已跳过，稍后可执行 ipchange test。" ;;
        *) run_with_progress "发送 Telegram 测试通知" "$BIN" test || warn=1 ;;
    esac

    say
    say "=================================================="
    if [ "$warn" -eq 0 ]; then
        say "✅ ipchange Enterprise v$VERSION 安装完成"
    else
        say "⚠️ ipchange Enterprise v$VERSION 安装完成，但有警告/失败项"
    fi
    say "=================================================="
    say "安装脚本：ipchange.sh"
    say "目录：$ROOT_DIR"
    say "配置：$CONF"
    say "状态：$STATE_DIR"
    say "日志：$LOG_DIR"
    if grep -q '^CLEANUP_DAYS=0$' "$CONF" 2>/dev/null; then
        say "自动清理：关闭"
    else
        say "自动清理：$(grep '^CLEANUP_DAYS=' "$CONF" 2>/dev/null | cut -d= -f2 | tr -d "'\"") 天"
    fi
    say
    say "以后查看后台定时状态，直接："
    say "  ipchange status"
    say "  ipchange monitor"
    say
    say "其它："
    say "  ipchange doctor"
    say "  ipchange service-test"
    say "  ipchange test"
    say "  ipchange cf-test"
    say "  ipchange geotest"
    say "  ipchange logs"
    say "  ipchange cleanup"

    return 0
}

main "$@"
