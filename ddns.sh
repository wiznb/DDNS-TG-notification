#!/usr/bin/env bash
# Cloudflare DDNS (IPv4+IPv6) + Telegram notify
# Works on CentOS/Debian/Ubuntu/Alpine
# Config/logs live in: /root/ddns

set -u
set -o pipefail

BASE_DIR="/root/ddns"
CONF_FILE="$BASE_DIR/config.env"
CACHE_FILE="$BASE_DIR/cache.env"

FAIL_LOG_PREFIX="run"
FAIL_KEEP_DAYS=3

CHANGE_LOG_FILE="$BASE_DIR/chip.log"
CHANGE_KEEP_DAYS=30

LOCK_DIR="$BASE_DIR/.lock"
LOCK_PID_FILE="$LOCK_DIR/pid"
LOCK_TIME_FILE="$LOCK_DIR/start_epoch"
LOCK_CMD_FILE="$LOCK_DIR/cmd"
LOCK_HOST_FILE="$LOCK_DIR/host"
LOCK_STALE_SECONDS="${LOCK_STALE_SECONDS:-1800}"

CF_API_BASE="https://api.cloudflare.com/client/v4"

ensure_base_dir() {
  mkdir -p "$BASE_DIR"
  chmod 700 "$BASE_DIR" 2>/dev/null || true
}

bj_now()   { TZ="Asia/Shanghai" date "+%Y-%m-%d %H:%M:%S"; }
bj_day()   { TZ="Asia/Shanghai" date "+%Y-%m-%d"; }
bj_epoch() { TZ="Asia/Shanghai" date "+%s"; }

say() { printf "%s\n" "$*"; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

fail_log_file() {
  echo "$BASE_DIR/${FAIL_LOG_PREFIX}_$(bj_day).log"
}

log_fail() {
  ensure_base_dir
  local ts msg f
  ts="$(bj_now)"
  msg="$*"
  f="$(fail_log_file)"
  printf "[%s] FAIL %s\n" "$ts" "$msg" >> "$f"
}

prune_fail_logs() {
  local keep_plus=$((FAIL_KEEP_DAYS - 1))
  find "$BASE_DIR" -maxdepth 1 -type f -name "${FAIL_LOG_PREFIX}_*.log" -mtime "+${keep_plus}" -delete 2>/dev/null || true
}

prune_change_log_30d() {
  [ -f "$CHANGE_LOG_FILE" ] || return 0
  local now cut
  now="$(bj_epoch)"
  cut=$((now - CHANGE_KEEP_DAYS*86400))

  awk -v cut="$cut" '
    $1 ~ /^[0-9]+$/ && $1 >= cut {print}
  ' "$CHANGE_LOG_FILE" > "${CHANGE_LOG_FILE}.tmp" 2>/dev/null && mv -f "${CHANGE_LOG_FILE}.tmp" "$CHANGE_LOG_FILE"
}

log_change() {
  ensure_base_dir
  local epoch ts
  epoch="$(bj_epoch)"
  ts="$(bj_now)"
  printf "%s [%s] %s\n" "$epoch" "$ts" "$*" >> "$CHANGE_LOG_FILE"
  prune_change_log_30d
}

# -------------------------
# Lock optimized
# -------------------------
current_script_path() {
  readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0"
}

process_cmdline() {
  local pid="$1"
  if [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//'
  else
    ps -p "$pid" -o args= 2>/dev/null || true
  fi
}

pid_running() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1

  local stat
  stat="$(ps -p "$pid" -o stat= 2>/dev/null | awk '{print $1}' || true)"
  case "$stat" in
    Z*) return 1 ;;
  esac

  return 0
}

lock_age_seconds() {
  local start now
  start=""
  [ -f "$LOCK_TIME_FILE" ] && start="$(cat "$LOCK_TIME_FILE" 2>/dev/null || true)"
  [[ "$start" =~ ^[0-9]+$ ]] || {
    echo ""
    return 0
  }
  now="$(date "+%s")"
  echo $((now - start))
}

write_lock_meta() {
  ensure_base_dir
  printf "%s\n" "$$" > "$LOCK_PID_FILE"
  date "+%s" > "$LOCK_TIME_FILE"
  process_cmdline "$$" > "$LOCK_CMD_FILE" 2>/dev/null || printf "%s\n" "bash $(current_script_path)" > "$LOCK_CMD_FILE"
  hostname 2>/dev/null > "$LOCK_HOST_FILE" || true
}

release_lock() {
  if [ -d "$LOCK_DIR" ]; then
    local old_pid
    old_pid="$(cat "$LOCK_PID_FILE" 2>/dev/null || true)"
    if [ "$old_pid" = "$$" ]; then
      rm -rf "$LOCK_DIR" 2>/dev/null || true
    fi
  fi
}

show_lock_status() {
  ensure_base_dir

  if [ ! -d "$LOCK_DIR" ]; then
    say "[OK] 当前没有锁：$LOCK_DIR"
    return 0
  fi

  local pid start age cmd host state
  pid="$(cat "$LOCK_PID_FILE" 2>/dev/null || true)"
  start="$(cat "$LOCK_TIME_FILE" 2>/dev/null || true)"
  age="$(lock_age_seconds)"
  cmd="$(cat "$LOCK_CMD_FILE" 2>/dev/null || true)"
  host="$(cat "$LOCK_HOST_FILE" 2>/dev/null || true)"

  if pid_running "$pid"; then
    state="running"
  else
    state="stale/dead"
  fi

  say "========== DDNS Lock Status =========="
  say "锁目录: $LOCK_DIR"
  say "状态:   $state"
  say "PID:    ${pid:-unknown}"
  say "Host:   ${host:-unknown}"
  say "Start:  ${start:-unknown}"
  if [ -n "$age" ]; then
    say "Age:    ${age}s"
  else
    say "Age:    unknown"
  fi
  say "Cmd:    ${cmd:-unknown}"

  if [ "$state" = "running" ]; then
    say ""
    say "[HINT] 如果确认不是 ddns 任务，可执行：bash $0 --force-unlock"
  else
    say ""
    say "[HINT] 这是残留锁，可执行：bash $0 --unlock"
  fi
}

safe_unlock() {
  ensure_base_dir

  if [ ! -d "$LOCK_DIR" ]; then
    say "[OK] 当前没有锁，无需清理。"
    return 0
  fi

  local pid
  pid="$(cat "$LOCK_PID_FILE" 2>/dev/null || true)"

  if pid_running "$pid"; then
    say "[WARN] 锁内 PID 仍在运行，安全模式不删除锁。"
    show_lock_status
    say ""
    say "[HINT] 如果确认是误判或旧 PID，可使用：bash $0 --force-unlock"
    return 1
  fi

  rm -rf "$LOCK_DIR" 2>/dev/null || true
  say "[OK] 已清理残留锁：$LOCK_DIR"
  return 0
}

force_unlock() {
  ensure_base_dir
  if [ ! -d "$LOCK_DIR" ]; then
    say "[OK] 当前没有锁，无需强制清理。"
    return 0
  fi
  rm -rf "$LOCK_DIR" 2>/dev/null || true
  say "[OK] 已强制清理锁：$LOCK_DIR"
}

acquire_lock() {
  ensure_base_dir

  if mkdir "$LOCK_DIR" 2>/dev/null; then
    write_lock_meta
    trap release_lock EXIT INT TERM
    return 0
  fi

  local old_pid old_age old_cmd
  old_pid="$(cat "$LOCK_PID_FILE" 2>/dev/null || true)"
  old_age="$(lock_age_seconds)"
  old_cmd="$(cat "$LOCK_CMD_FILE" 2>/dev/null || true)"

  if [ -z "$old_pid" ]; then
    say "[WARN] 发现无 PID 的残留锁，自动清理：$LOCK_DIR"
    rm -rf "$LOCK_DIR" 2>/dev/null || true
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      write_lock_meta
      trap release_lock EXIT INT TERM
      return 0
    fi
  fi

  if ! pid_running "$old_pid"; then
    say "[WARN] 发现残留死锁，PID 不存在或已退出：$old_pid"
    say "[INFO] 自动清理残留锁：$LOCK_DIR"
    rm -rf "$LOCK_DIR" 2>/dev/null || true

    if mkdir "$LOCK_DIR" 2>/dev/null; then
      write_lock_meta
      trap release_lock EXIT INT TERM
      return 0
    fi

    say "[WARN] 清理后仍无法获取锁，可能刚好有新任务启动。"
    return 1
  fi

  say "[WARN] 检测到已有 DDNS 任务正在运行，本次退出避免并发。"
  say "[INFO] 锁目录：$LOCK_DIR"
  say "[INFO] PID：$old_pid"
  if [ -n "$old_age" ]; then
    say "[INFO] 已运行：${old_age}s"
    if [ "$old_age" -gt "$LOCK_STALE_SECONDS" ]; then
      say "[WARN] 该任务运行时间超过 ${LOCK_STALE_SECONDS}s，建议检查是否卡住。"
    fi
  fi
  say "[INFO] 命令：${old_cmd:-unknown}"
  say "[HINT] 查看锁：bash $0 --lock-status"
  say "[HINT] 安全清理死锁：bash $0 --unlock"
  say "[HINT] 确认无任务后强制清理：bash $0 --force-unlock"
  return 1
}

lock_manage_interactive() {
  show_lock_status
  say ""
  say "1) 安全清理残留锁（只清理 PID 不存在/已退出的锁）"
  say "2) 强制清理锁（确认没有任务在跑再用）"
  say "0) 返回"
  read -r -p "请选择: " opt
  case "${opt:-}" in
    1) safe_unlock ;;
    2) force_unlock ;;
    0) return 0 ;;
    *) say "[ERR] 无效选择" ;;
  esac
}

# -------------------------
# Deps
# -------------------------
detect_pkg_mgr() {
  if need_cmd apt-get; then echo "apt"
  elif need_cmd dnf; then echo "dnf"
  elif need_cmd yum; then echo "yum"
  elif need_cmd apk; then echo "apk"
  else echo "none"
  fi
}

install_deps() {
  if [ "$(id -u)" -ne 0 ]; then
    say "[ERR] 安装依赖需要 root。请用 root 执行：bash ddns.sh --install-deps"
    return 1
  fi

  local pm
  pm="$(detect_pkg_mgr)"

  case "$pm" in
    apt)
      say "[INFO] 使用 apt 安装依赖：curl jq cron bash"
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq cron bash
      ;;
    dnf)
      say "[INFO] 使用 dnf 安装依赖：curl jq cronie bash"
      dnf install -y curl jq cronie bash
      ;;
    yum)
      say "[INFO] 使用 yum 安装依赖：curl jq cronie bash"
      yum install -y curl jq cronie bash
      ;;
    apk)
      say "[INFO] 使用 apk 安装依赖：bash curl jq dcron"
      apk add --no-cache bash curl jq dcron
      ;;
    *)
      say "[ERR] 未识别的包管理器，无法自动安装。请手动安装：bash curl jq（以及 cron）"
      return 1
      ;;
  esac

  say "[OK] 依赖安装完成。"
  return 0
}

ensure_deps() {
  local missing=0
  for c in curl jq; do
    if ! need_cmd "$c"; then
      say "[WARN] 缺少依赖：$c"
      missing=1
    fi
  done

  if ! need_cmd bash; then
    say "[WARN] 系统可能没有 bash（Alpine 常见）。建议：apk add --no-cache bash"
  fi

  if [ "$missing" -eq 1 ]; then
    say "[HINT] 可执行：bash ddns.sh --install-deps 自动安装依赖（需 root）。"
    return 1
  fi

  return 0
}

# -------------------------
# Config
# -------------------------
load_config_strict() {
  if [ ! -f "$CONF_FILE" ]; then
    return 1
  fi

  # shellcheck disable=SC1090
  source "$CONF_FILE"

  : "${CFZONE_NAME:?missing CFZONE_NAME}"
  : "${CFRECORD_NAME:?missing CFRECORD_NAME}"

  CF_AUTH_MODE="${CF_AUTH_MODE:-global}"
  ENABLE_IPV4="${ENABLE_IPV4:-1}"
  ENABLE_IPV6="${ENABLE_IPV6:-0}"
  PROXIED="${PROXIED:-false}"
  TTL="${TTL:-1}"

  TELEGRAM_ENABLE="${TELEGRAM_ENABLE:-0}"
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
  TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

  if [ "$CF_AUTH_MODE" = "token" ]; then
    : "${CF_API_TOKEN:?missing CF_API_TOKEN}"
  else
    : "${CF_EMAIL:?missing CF_EMAIL}"
    : "${CF_API_KEY:?missing CF_API_KEY}"
  fi

  return 0
}

load_config_soft() {
  if [ -f "$CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
  fi

  CF_AUTH_MODE="${CF_AUTH_MODE:-global}"
  ENABLE_IPV4="${ENABLE_IPV4:-1}"
  ENABLE_IPV6="${ENABLE_IPV6:-0}"
  PROXIED="${PROXIED:-false}"
  TTL="${TTL:-1}"

  TELEGRAM_ENABLE="${TELEGRAM_ENABLE:-0}"
  TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
  TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

  return 0
}

write_config_interactive() {
  ensure_base_dir
  umask 077

  say "========== Cloudflare DDNS 配置 =========="
  say "认证方式："
  say "  1) Global API Key（CF_EMAIL + CF_API_KEY）"
  say "  2) API Token（更推荐，更安全）"
  say ""

  read -r -p "选择认证方式 [1=GlobalKey, 2=Token]（默认1）: " mode
  mode="${mode:-1}"

  local CF_AUTH_MODE_in="global"
  local CF_API_KEY_in="" CF_EMAIL_in="" CF_API_TOKEN_in=""
  local CFZONE_NAME_in="" CFRECORD_NAME_in=""
  local ENABLE_IPV4_in="1" ENABLE_IPV6_in="0"
  local PROXIED_in="false" TTL_in="1"

  if [ "$mode" = "2" ]; then
    CF_AUTH_MODE_in="token"
    read -r -p 'CF_API_TOKEN="你的API Token": ' CF_API_TOKEN_in
  else
    CF_AUTH_MODE_in="global"
    read -r -p 'CF_API_KEY="你的GlobalAPIKey": ' CF_API_KEY_in
    read -r -p 'CF_EMAIL="你的Cloudflare邮箱": ' CF_EMAIL_in
  fi

  read -r -p 'CFZONE_NAME="example.com": ' CFZONE_NAME_in
  read -r -p 'CFRECORD_NAME="home.example.com": ' CFRECORD_NAME_in

  say ""
  say "更新模式："
  say "  1) 只更新 IPv4 (A)"
  say "  2) 只更新 IPv6 (AAAA)"
  say "  3) IPv4 + IPv6 都更新"
  read -r -p "请选择 [1/2/3]（默认1）: " ipmode
  ipmode="${ipmode:-1}"

  case "$ipmode" in
    2) ENABLE_IPV4_in="0"; ENABLE_IPV6_in="1" ;;
    3) ENABLE_IPV4_in="1"; ENABLE_IPV6_in="1" ;;
    *) ENABLE_IPV4_in="1"; ENABLE_IPV6_in="0" ;;
  esac

  read -r -p "Cloudflare 代理（橙云）？[true/false]（默认false）: " PROXIED_in
  PROXIED_in="${PROXIED_in:-false}"

  read -r -p "TTL（1=auto）默认1: " TTL_in
  TTL_in="${TTL_in:-1}"

  cat > "$CONF_FILE" <<EOF
# Cloudflare DDNS config
CF_AUTH_MODE="${CF_AUTH_MODE_in}"

CF_API_KEY="${CF_API_KEY_in}"
CF_EMAIL="${CF_EMAIL_in}"

CF_API_TOKEN="${CF_API_TOKEN_in}"

CFZONE_NAME="${CFZONE_NAME_in}"
CFRECORD_NAME="${CFRECORD_NAME_in}"

ENABLE_IPV4="${ENABLE_IPV4_in}"
ENABLE_IPV6="${ENABLE_IPV6_in}"

PROXIED="${PROXIED_in}"
TTL="${TTL_in}"

TELEGRAM_ENABLE="${TELEGRAM_ENABLE:-0}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
EOF

  chmod 600 "$CONF_FILE" 2>/dev/null || true
  say "[OK] 已保存配置到：$CONF_FILE"
}

env_set_kv() {
  local key="$1" val="$2"
  ensure_base_dir
  touch "$CONF_FILE"
  chmod 600 "$CONF_FILE" 2>/dev/null || true

  local esc
  esc="$(printf '%s' "$val" | sed 's/\\/\\\\/g; s/"/\\"/g')"

  awk -v k="$key" -v v="$esc" '
    BEGIN{found=0}
    $0 ~ "^"k"=" {
      print k"=\""v"\""
      found=1
      next
    }
    {print}
    END{
      if(found==0) print k"=\""v"\""
    }
  ' "$CONF_FILE" > "${CONF_FILE}.tmp" && mv -f "${CONF_FILE}.tmp" "$CONF_FILE"
}

# -------------------------
# Telegram
# -------------------------
tg_enabled() {
  [ "${TELEGRAM_ENABLE:-0}" = "1" ] && [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]
}

tg_send() {
  local text="$1"
  if ! tg_enabled; then
    return 0
  fi

  local api="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"

  if ! curl -fsS --max-time 10 -X POST "$api" \
      -d "chat_id=${TELEGRAM_CHAT_ID}" \
      -d "disable_web_page_preview=true" \
      --data-urlencode "text=${text}" >/dev/null 2>&1; then
    log_fail "Telegram 通知发送失败（chat_id=${TELEGRAM_CHAT_ID}）"
    return 1
  fi

  return 0
}

tg_notify_change() {
  local action="$1" type="$2" name="$3" old="$4" new="$5"
  local ts msg
  ts="$(bj_now)"

  msg="Cloudflare DDNS 变更通知
Record: ${name}
Type: ${type}
Action: ${action}
Current IP: ${new}"

  if [ -n "$old" ] && [ "$old" != "<none>" ]; then
    msg="${msg}
Old IP: ${old}"
  fi

  msg="${msg}
Time(BJ): ${ts}"

  tg_send "$msg" || true
}

telegram_config_interactive() {
  ensure_base_dir
  umask 077
  ensure_deps || return 1
  load_config_soft

  say "========== Telegram 通知配置 =========="
  say "只修改 Telegram 字段：TELEGRAM_ENABLE / TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID"
  say ""

  local en token chat
  read -r -p "启用 Telegram 通知？[1=是,0=否]（默认0）: " en
  en="${en:-0}"

  if [ "$en" = "1" ]; then
    read -r -p 'TELEGRAM_BOT_TOKEN="你的Bot Token": ' token
    read -r -p 'TELEGRAM_CHAT_ID="你的Chat ID/群ID": ' chat

    env_set_kv "TELEGRAM_ENABLE" "1"
    env_set_kv "TELEGRAM_BOT_TOKEN" "$token"
    env_set_kv "TELEGRAM_CHAT_ID" "$chat"

    load_config_soft

    say "[OK] Telegram 已启用并写入：$CONF_FILE"
    say "[INFO] 现在自动发送一条测试通知..."
    telegram_test || true
  else
    env_set_kv "TELEGRAM_ENABLE" "0"
    env_set_kv "TELEGRAM_BOT_TOKEN" ""
    env_set_kv "TELEGRAM_CHAT_ID" ""
    say "[OK] Telegram 已关闭。"
  fi
}

# -------------------------
# IP detect
# -------------------------
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

valid_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

valid_ipv6() {
  [[ "$1" =~ : ]]
}

get_ipv4() {
  local ip=""
  ip="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null | trim || true)"

  if [ -z "$ip" ]; then
    ip="$(curl -4 -fsS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | trim || true)"
  fi

  if [ -n "$ip" ] && valid_ipv4 "$ip"; then
    echo "$ip"
  else
    echo ""
  fi
}

get_ipv6() {
  local ip=""
  ip="$(curl -6 -fsS --max-time 6 https://api64.ipify.org 2>/dev/null | trim || true)"

  if [ -z "$ip" ]; then
    ip="$(curl -6 -fsS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | trim || true)"
  fi

  if [ -n "$ip" ] && valid_ipv6 "$ip"; then
    echo "$ip"
  else
    echo ""
  fi
}

# -------------------------
# Cloudflare API
# -------------------------
cf_headers() {
  if [ "${CF_AUTH_MODE:-global}" = "token" ]; then
    printf "Authorization: Bearer %s\n" "$CF_API_TOKEN"
  else
    printf "X-Auth-Email: %s\nX-Auth-Key: %s\n" "$CF_EMAIL" "$CF_API_KEY"
  fi

  printf "Content-Type: application/json\n"
}

cf_api() {
  local method="$1" path="$2" data="${3:-}"
  local url="${CF_API_BASE}${path}"
  local -a hdr_args=()
  local line

  while IFS= read -r line; do
    [ -n "$line" ] && hdr_args+=(-H "$line")
  done < <(cf_headers)

  if [ -n "$data" ]; then
    curl -fsS -X "$method" "${hdr_args[@]}" --data "$data" "$url"
  else
    curl -fsS -X "$method" "${hdr_args[@]}" "$url"
  fi
}

cache_get() {
  local key="$1"

  if [ -f "$CACHE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CACHE_FILE"
    eval "echo \"\${$key:-}\""
  else
    echo ""
  fi
}

cache_set() {
  ensure_base_dir
  local key="$1" val="$2"

  touch "$CACHE_FILE"
  chmod 600 "$CACHE_FILE" 2>/dev/null || true

  grep -vE "^${key}=" "$CACHE_FILE" > "${CACHE_FILE}.tmp" 2>/dev/null || true
  mv -f "${CACHE_FILE}.tmp" "$CACHE_FILE"
  printf '%s="%s"\n' "$key" "$val" >> "$CACHE_FILE"
}

get_zone_id() {
  local zid
  zid="$(cache_get ZONE_ID)"

  if [ -n "$zid" ]; then
    echo "$zid"
    return 0
  fi

  local resp
  resp="$(cf_api GET "/zones?name=${CFZONE_NAME}" 2>/dev/null)" || return 1
  zid="$(echo "$resp" | jq -r '.result[0].id // empty')"

  [ -n "$zid" ] && [ "$zid" != "null" ] || return 1

  cache_set ZONE_ID "$zid"
  echo "$zid"
}

get_record_info() {
  local zid="$1" type="$2" name="$3"
  local resp id content

  resp="$(cf_api GET "/zones/${zid}/dns_records?type=${type}&name=${name}&per_page=1" 2>/dev/null)" || return 1

  id="$(echo "$resp" | jq -r '.result[0].id // empty')"
  content="$(echo "$resp" | jq -r '.result[0].content // empty')"

  printf "%s|%s\n" "$id" "$content"
}

create_record() {
  local zid="$1" type="$2" name="$3" content="$4"
  local data resp id

  data="$(jq -nc \
    --arg type "$type" \
    --arg name "$name" \
    --arg content "$content" \
    --argjson ttl "${TTL}" \
    --argjson proxied "$( [ "$PROXIED" = "true" ] && echo true || echo false )" \
    '{type:$type,name:$name,content:$content,ttl:$ttl,proxied:$proxied}')"

  resp="$(cf_api POST "/zones/${zid}/dns_records" "$data" 2>/dev/null)" || return 1
  id="$(echo "$resp" | jq -r '.result.id // empty')"

  [ -n "$id" ] && echo "$id"
}

update_record() {
  local zid="$1" rid="$2" type="$3" name="$4" content="$5"
  local data resp ok

  data="$(jq -nc \
    --arg type "$type" \
    --arg name "$name" \
    --arg content "$content" \
    --argjson ttl "${TTL}" \
    --argjson proxied "$( [ "$PROXIED" = "true" ] && echo true || echo false )" \
    '{type:$type,name:$name,content:$content,ttl:$ttl,proxied:$proxied}')"

  resp="$(cf_api PUT "/zones/${zid}/dns_records/${rid}" "$data" 2>/dev/null)" || return 1
  ok="$(echo "$resp" | jq -r '.success')"

  [ "$ok" = "true" ]
}

ddns_update_one() {
  local type="$1" ip="$2"

  local zid
  zid="$(get_zone_id)" || {
    say "[ERR] 获取 Zone ID 失败（检查 CFZONE_NAME / 认证信息）"
    log_fail "ZoneID 获取失败（zone=${CFZONE_NAME}, type=${type}）"
    return 1
  }

  local info rid old
  info="$(get_record_info "$zid" "$type" "$CFRECORD_NAME")" || {
    say "[ERR] 查询 DNS Record 失败（type=$type name=$CFRECORD_NAME）"
    log_fail "Record 查询失败（type=${type}, name=${CFRECORD_NAME}）"
    return 1
  }

  rid="${info%%|*}"
  old="${info#*|}"

  if [ -z "$rid" ]; then
    say "[INFO] 未找到 $type 记录，将创建：$CFRECORD_NAME -> $ip"

    rid="$(create_record "$zid" "$type" "$CFRECORD_NAME" "$ip")" || {
      say "[ERR] 创建记录失败（type=$type）"
      log_fail "创建记录失败（type=${type}, name=${CFRECORD_NAME}, ip=${ip}）"
      return 1
    }

    say "[OK] 已创建 $type 记录：$CFRECORD_NAME -> $ip"
    log_change "CREATED ${type} ${CFRECORD_NAME} new=${ip}"
    tg_notify_change "CREATED" "$type" "$CFRECORD_NAME" "<none>" "$ip"
    return 0
  fi

  if [ "$old" = "$ip" ]; then
    say "[OK] $type 无需更新：$CFRECORD_NAME 当前=$old"
    return 0
  fi

  say "[INFO] 准备更新 $type：$CFRECORD_NAME $old -> $ip"

  if update_record "$zid" "$rid" "$type" "$CFRECORD_NAME" "$ip"; then
    say "[OK] 更新成功 $type：$CFRECORD_NAME $old -> $ip"
    log_change "UPDATED ${type} ${CFRECORD_NAME} old=${old} new=${ip}"
    tg_notify_change "UPDATED" "$type" "$CFRECORD_NAME" "$old" "$ip"
    return 0
  else
    say "[ERR] 更新失败 $type：$CFRECORD_NAME"
    log_fail "更新失败（type=${type}, name=${CFRECORD_NAME}, old=${old}, new=${ip}）"
    return 1
  fi
}

# -------------------------
# Telegram test
# -------------------------
cf_ready_for_query() {
  if [ -z "${CFZONE_NAME:-}" ] || [ -z "${CFRECORD_NAME:-}" ]; then
    return 1
  fi

  if [ "${CF_AUTH_MODE:-global}" = "token" ]; then
    [ -n "${CF_API_TOKEN:-}" ]
  else
    [ -n "${CF_EMAIL:-}" ] && [ -n "${CF_API_KEY:-}" ]
  fi
}

telegram_test() {
  ensure_base_dir
  prune_fail_logs
  prune_change_log_30d

  ensure_deps || return 1
  load_config_soft

  if ! tg_enabled; then
    say "[ERR] Telegram 未启用或配置不完整：TELEGRAM_ENABLE/TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID"
    log_fail "Telegram 测试失败：未启用或配置不完整"
    return 1
  fi

  local ts a_local v6_local a_cf v6_cf
  ts="$(bj_now)"

  a_local="(disabled)"
  v6_local="(disabled)"

  if [ "${ENABLE_IPV4:-1}" = "1" ]; then
    a_local="$(get_ipv4)"
    [ -z "$a_local" ] && a_local="(get ipv4 fail)"
  fi

  if [ "${ENABLE_IPV6:-0}" = "1" ]; then
    v6_local="$(get_ipv6)"
    [ -z "$v6_local" ] && v6_local="(get ipv6 fail)"
  fi

  a_cf="(skip)"
  v6_cf="(skip)"

  if cf_ready_for_query; then
    local zid infoA infoAAAA
    zid="$(get_zone_id 2>/dev/null || true)"

    if [ -n "$zid" ]; then
      if [ "${ENABLE_IPV4:-1}" = "1" ]; then
        infoA="$(get_record_info "$zid" "A" "$CFRECORD_NAME" 2>/dev/null || true)"
        a_cf="${infoA#*|}"
        [ -z "$a_cf" ] && a_cf="(none)"
      fi

      if [ "${ENABLE_IPV6:-0}" = "1" ]; then
        infoAAAA="$(get_record_info "$zid" "AAAA" "$CFRECORD_NAME" 2>/dev/null || true)"
        v6_cf="${infoAAAA#*|}"
        [ -z "$v6_cf" ] && v6_cf="(none)"
      fi
    else
      a_cf="(zone_id fail)"
      v6_cf="(zone_id fail)"
    fi
  else
    a_cf="(CF not configured)"
    v6_cf="(CF not configured)"
  fi

  local name zone
  name="${CFRECORD_NAME:-"(not set)"}"
  zone="${CFZONE_NAME:-"(not set)"}"

  local msg="DDNS Telegram 测试通知
Record: ${name}
Zone: ${zone}
IPv4 local: ${a_local}
IPv4 CF(A): ${a_cf}
IPv6 local: ${v6_local}
IPv6 CF(AAAA): ${v6_cf}
Time(BJ): ${ts}"

  if tg_send "$msg"; then
    say "[OK] Telegram 测试通知已发送。"
    return 0
  else
    say "[ERR] Telegram 测试通知发送失败（详见失败日志：$(fail_log_file)）"
    return 1
  fi
}

# -------------------------
# Run once
# -------------------------
run_once() {
  ensure_base_dir
  prune_fail_logs
  prune_change_log_30d

  ensure_deps || return 1

  load_config_strict || {
    say "[ERR] 找不到配置或配置不完整：$CONF_FILE"
    say "[HINT] 运行：bash ddns.sh 进入交互配置"
    return 1
  }

  if [ "${ENABLE_IPV4}" != "1" ] && [ "${ENABLE_IPV6}" != "1" ]; then
    say "[ERR] 配置错误：IPv4/IPv6 都未启用（请重新配置）"
    log_fail "配置错误：IPv4/IPv6 都未启用"
    return 1
  fi

  acquire_lock || return 0

  say "========== Cloudflare DDNS 执行（北京时间：$(bj_now)） =========="
  say "[INFO] Zone:   $CFZONE_NAME"
  say "[INFO] Record: $CFRECORD_NAME"
  say "[INFO] IPv4:   ENABLE=${ENABLE_IPV4}  | IPv6: ENABLE=${ENABLE_IPV6}"
  say "[INFO] Telegram: ENABLE=${TELEGRAM_ENABLE}"
  say ""

  local rc=0 v4 v6

  if [ "${ENABLE_IPV4}" = "1" ]; then
    v4="$(get_ipv4)"

    if [ -n "$v4" ]; then
      say "[INFO] 读取到公网 IPv4：$v4"
      ddns_update_one "A" "$v4" || rc=1
    else
      say "[ERR] 未能获取公网 IPv4（A 记录无法更新）"
      log_fail "获取IPv4失败（A记录无法更新）"
      rc=1
    fi

    say ""
  fi

  if [ "${ENABLE_IPV6}" = "1" ]; then
    v6="$(get_ipv6)"

    if [ -n "$v6" ]; then
      say "[INFO] 读取到公网 IPv6：$v6"
      ddns_update_one "AAAA" "$v6" || rc=1
    else
      say "[ERR] 未能获取公网 IPv6（AAAA 记录无法更新）"
      log_fail "获取IPv6失败（AAAA记录无法更新；如无IPv6请在交互里选择“只更新IPv4”）"
      rc=1
    fi

    say ""
  fi

  if [ "$rc" -eq 0 ]; then
    say "========== 完成：全部成功 =========="
  else
    say "========== 完成：存在失败（失败详情见：$(fail_log_file)） =========="
  fi

  return "$rc"
}

# -------------------------
# Cron
# -------------------------
cron_line() {
  local script_path
  script_path="$(current_script_path)"
  echo "* * * * * bash \"$script_path\" --run >/dev/null 2>&1 # CF_DDNS"
}

install_cron() {
  ensure_deps || return 1
  local line
  line="$(cron_line)"

  if need_cmd crontab; then
    (crontab -l 2>/dev/null | grep -v ' # CF_DDNS$' ; echo "$line") | crontab -
    say "[OK] 已安装 crontab（每1分钟执行一次）。"
  else
    if [ "$(id -u)" -ne 0 ]; then
      say "[ERR] Alpine 写 /etc/crontabs/root 需要 root。"
      return 1
    fi

    mkdir -p /etc/crontabs
    touch /etc/crontabs/root
    grep -v ' # CF_DDNS$' /etc/crontabs/root > /etc/crontabs/root.tmp 2>/dev/null || true
    printf "%s\n" "$line" >> /etc/crontabs/root.tmp
    mv -f /etc/crontabs/root.tmp /etc/crontabs/root
    say "[OK] 已写入 /etc/crontabs/root（每1分钟执行一次）。"
  fi

  say ""
  say "[HINT] 如果定时不生效，请确保 cron 服务在运行："
  say "  - Debian/Ubuntu: systemctl enable --now cron"
  say "  - CentOS/RHEL:   systemctl enable --now crond"
  say "  - Alpine(OpenRC): rc-update add crond default && rc-service crond start"
}

uninstall_cron() {
  if need_cmd crontab; then
    (crontab -l 2>/dev/null | grep -v ' # CF_DDNS$') | crontab - 2>/dev/null || true
    say "[OK] 已移除 crontab 里的 CF_DDNS 定时。"
  else
    if [ "$(id -u)" -ne 0 ]; then
      say "[ERR] Alpine 修改 /etc/crontabs/root 需要 root。"
      return 1
    fi

    if [ -f /etc/crontabs/root ]; then
      grep -v ' # CF_DDNS$' /etc/crontabs/root > /etc/crontabs/root.tmp 2>/dev/null || true
      mv -f /etc/crontabs/root.tmp /etc/crontabs/root
      say "[OK] 已移除 /etc/crontabs/root 里的 CF_DDNS 定时。"
    else
      say "[INFO] 未发现 /etc/crontabs/root"
    fi
  fi
}

# -------------------------
# Info / Usage
# -------------------------
show_paths() {
  say "配置文件：$CONF_FILE"
  say "缓存文件：$CACHE_FILE"
  say "锁目录：$LOCK_DIR"
  say "失败日志：$BASE_DIR/${FAIL_LOG_PREFIX}_YYYY-MM-DD.log（北京时间，每天一个，保留${FAIL_KEEP_DAYS}天）"
  say "变更日志：$CHANGE_LOG_FILE（仅IP变更追加，保留近${CHANGE_KEEP_DAYS}天记录）"
}

usage() {
  cat <<EOF
用法：
  bash ddns.sh                      # 交互菜单
  bash ddns.sh --run                # 执行一次 DDNS
  bash ddns.sh --install-deps       # 安装依赖
  bash ddns.sh --install-cron       # 安装每1分钟执行的 cron
  bash ddns.sh --uninstall-cron     # 移除 cron
  bash ddns.sh --tg-config          # Telegram 独立交互配置
  bash ddns.sh --telegram-test      # 手动发送 Telegram 测试通知
  bash ddns.sh --show-paths         # 显示配置/日志路径

锁相关：
  bash ddns.sh --lock-status        # 查看当前锁状态
  bash ddns.sh --unlock             # 安全清理残留锁
  bash ddns.sh --force-unlock       # 强制清理锁
EOF
}

interactive_menu() {
  ensure_base_dir

  if [ ! -f "$CONF_FILE" ]; then
    write_config_interactive
    say ""
    run_once
    say ""
    show_paths
    return 0
  fi

  say "========== Cloudflare DDNS =========="
  say "1) 立即执行一次（--run）"
  say "2) 重新配置 Cloudflare/DDNS（覆盖 config.env）"
  say "3) 配置 Telegram（独立交互）"
  say "4) 发送 Telegram 测试通知（--telegram-test）"
  say "5) 安装 cron（每1分钟）"
  say "6) 移除 cron"
  say "7) 显示配置/日志路径"
  say "8) 查看/清理运行锁（解决 .lock 卡住）"
  say "0) 退出"

  read -r -p "请选择: " opt

  case "${opt:-}" in
    1) run_once ;;
    2) write_config_interactive ;;
    3) telegram_config_interactive ;;
    4) telegram_test ;;
    5) install_cron ;;
    6) uninstall_cron ;;
    7) show_paths ;;
    8) lock_manage_interactive ;;
    0) exit 0 ;;
    *) say "[ERR] 无效选择" ;;
  esac
}

# -------------------------
# main
# -------------------------
ensure_base_dir

case "${1:-}" in
  "" ) interactive_menu ;;
  --run ) run_once ;;
  --install-deps ) install_deps ;;
  --install-cron ) install_cron ;;
  --uninstall-cron ) uninstall_cron ;;
  --tg-config|--telegram-config ) telegram_config_interactive ;;
  --telegram-test ) telegram_test ;;
  --show-paths ) show_paths ;;
  --lock-status ) show_lock_status ;;
  --unlock ) safe_unlock ;;
  --force-unlock ) force_unlock ;;
  -h|--help ) usage ;;
  * ) usage; exit 1 ;;
esac
