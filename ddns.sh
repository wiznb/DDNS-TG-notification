#!/usr/bin/env bash
# Cloudflare DDNS (IPv4+IPv6) + Telegram notify
# Works on CentOS/Debian/Ubuntu/Alpine
# Config/logs live in: /root/ddns

set -u
set -o pipefail

BASE_DIR="/root/ddns"
CONF_FILE="$BASE_DIR/config.env"
CACHE_FILE="$BASE_DIR/cache.env"

# failure logs: /root/ddns/run_YYYY-MM-DD.log (Beijing time), keep 3 days
FAIL_LOG_PREFIX="run"
FAIL_KEEP_DAYS=3

# change log: /root/ddns/chip.log (single file), keep last 30 days records
CHANGE_LOG_FILE="$BASE_DIR/chip.log"
CHANGE_KEEP_DAYS=30

LOCK_DIR="$BASE_DIR/.lock"
CF_API_BASE="https://api.cloudflare.com/client/v4"

# -------------------------
# Time / Path
# -------------------------
ensure_base_dir() {
  mkdir -p "$BASE_DIR"
  chmod 700 "$BASE_DIR" 2>/dev/null || true
}
bj_now()   { TZ="Asia/Shanghai" date "+%Y-%m-%d %H:%M:%S"; }
bj_day()   { TZ="Asia/Shanghai" date "+%Y-%m-%d"; }
bj_epoch() { TZ="Asia/Shanghai" date "+%s"; }

# -------------------------
# Logs
# -------------------------
fail_log_file() {
  echo "$BASE_DIR/${FAIL_LOG_PREFIX}_$(bj_day).log"
}

log_fail() {
  # Only log failures
  ensure_base_dir
  local ts msg f
  ts="$(bj_now)"
  msg="$*"
  f="$(fail_log_file)"
  printf "[%s] FAIL %s\n" "$ts" "$msg" >> "$f"
}

prune_fail_logs() {
  # keep last FAIL_KEEP_DAYS days (including today): delete files older than keep_plus days by mtime
  local keep_plus=$((FAIL_KEEP_DAYS - 1))
  find "$BASE_DIR" -maxdepth 1 -type f -name "${FAIL_LOG_PREFIX}_*.log" -mtime "+${keep_plus}" -delete 2>/dev/null || true
}

prune_change_log_30d() {
  # keep only last 30 days records using epoch at the beginning of each line
  [ -f "$CHANGE_LOG_FILE" ] || return 0
  local now cut
  now="$(bj_epoch)"
  cut=$((now - CHANGE_KEEP_DAYS*86400))

  awk -v cut="$cut" '
    $1 ~ /^[0-9]+$/ && $1 >= cut {print}
  ' "$CHANGE_LOG_FILE" > "${CHANGE_LOG_FILE}.tmp" 2>/dev/null && mv -f "${CHANGE_LOG_FILE}.tmp" "$CHANGE_LOG_FILE"
}

log_change() {
  # only log when record is CREATED/UPDATED successfully
  ensure_base_dir
  local epoch ts
  epoch="$(bj_epoch)"
  ts="$(bj_now)"
  printf "%s [%s] %s\n" "$epoch" "$ts" "$*" >> "$CHANGE_LOG_FILE"
  prune_change_log_30d
}

# -------------------------
# Print
# -------------------------
say() { printf "%s\n" "$*"; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

# -------------------------
# Lock
# -------------------------
acquire_lock() {
  ensure_base_dir
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    trap 'rm -rf "$LOCK_DIR" 2>/dev/null || true' EXIT
    return 0
  else
    say "[WARN] 检测到已有任务在运行（锁：$LOCK_DIR），本次退出避免并发。"
    return 1
  fi
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
# Config load (strict for ddns run)
# -------------------------
load_config_strict() {
  if [ ! -f "$CONF_FILE" ]; then
    return 1
  fi
  # shellcheck disable=SC1090
  source "$CONF_FILE"

  : "${CFZONE_NAME:?missing CFZONE_NAME}"
  : "${CFRECORD_NAME:?missing CFRECORD_NAME}"

  CF_AUTH_MODE="${CF_AUTH_MODE:-global}"  # global | token
  ENABLE_IPV4="${ENABLE_IPV4:-1}"
  ENABLE_IPV6="${ENABLE_IPV6:-0}"         # default off to avoid v6-less machines
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

# soft load for telegram-only actions (don’t require CF fields)
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

# -------------------------
# Main config interactive (Cloudflare + DDNS mode)
# -------------------------
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
  say "更新模式（没 IPv6 就选“只更新 IPv4”，不会产生 IPv6 失败日志）："
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

  # Telegram fields are kept but not configured here (separate tg-config)
  cat > "$CONF_FILE" <<EOF
# Cloudflare DDNS config (stored in /root/ddns)
CF_AUTH_MODE="${CF_AUTH_MODE_in}"   # global | token

# Global API Key mode:
CF_API_KEY="${CF_API_KEY_in}"
CF_EMAIL="${CF_EMAIL_in}"

# API Token mode:
CF_API_TOKEN="${CF_API_TOKEN_in}"

CFZONE_NAME="${CFZONE_NAME_in}"
CFRECORD_NAME="${CFRECORD_NAME_in}"

# DDNS mode
ENABLE_IPV4="${ENABLE_IPV4_in}"
ENABLE_IPV6="${ENABLE_IPV6_in}"

PROXIED="${PROXIED_in}"   # true/false
TTL="${TTL_in}"           # 1 = auto

# Telegram notify (configure via: bash ddns.sh --tg-config)
TELEGRAM_ENABLE="${TELEGRAM_ENABLE:-0}"  # 1/0
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
EOF

  chmod 600 "$CONF_FILE" 2>/dev/null || true
  say "[OK] 已保存配置到：$CONF_FILE"
}

# -------------------------
# Edit config.env helper (set KEY="VALUE")
# -------------------------
env_set_kv() {
  local key="$1" val="$2"
  ensure_base_dir
  touch "$CONF_FILE"
  chmod 600 "$CONF_FILE" 2>/dev/null || true

  # escape \ and "
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
# Telegram (separate config + notify + test)
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
  # args: action type name old new
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

  say "========== Telegram 通知配置（独立交互） =========="
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

    # reload
    load_config_soft

    say "[OK] Telegram 已启用并写入：$CONF_FILE"
    say "[INFO] 现在自动发送一条测试通知（用于确认配置可用）..."
    telegram_test || true
  else
    env_set_kv "TELEGRAM_ENABLE" "0"
    env_set_kv "TELEGRAM_BOT_TOKEN" ""
    env_set_kv "TELEGRAM_CHAT_ID" ""
    say "[OK] Telegram 已关闭（并清空 token/chat_id）。"
  fi
}

# -------------------------
# IP Detect
# -------------------------
trim() { sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
valid_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
valid_ipv6() { [[ "$1" =~ : ]]; }

get_ipv4() {
  local ip=""
  ip="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null | trim || true)"
  if [ -z "$ip" ]; then
    ip="$(curl -4 -fsS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | trim || true)"
  fi
  if [ -n "$ip" ] && valid_ipv4 "$ip"; then echo "$ip"; else echo ""; fi
}

get_ipv6() {
  local ip=""
  ip="$(curl -6 -fsS --max-time 6 https://api64.ipify.org 2>/dev/null | trim || true)"
  if [ -z "$ip" ]; then
    ip="$(curl -6 -fsS --max-time 6 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | trim || true)"
  fi
  if [ -n "$ip" ] && valid_ipv6 "$ip"; then echo "$ip"; else echo ""; fi
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
  if [ -n "$zid" ]; then echo "$zid"; return 0; fi

  local resp
  resp="$(cf_api GET "/zones?name=${CFZONE_NAME}" 2>/dev/null)" || return 1
  zid="$(echo "$resp" | jq -r '.result[0].id // empty')"
  [ -n "$zid" ] && [ "$zid" != "null" ] || return 1
  cache_set ZONE_ID "$zid"
  echo "$zid"
}

get_record_info() {
  # output: id|content (may be empty)
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
    --arg type "$type" --arg name "$name" --arg content "$content" \
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
    --arg type "$type" --arg name "$name" --arg content "$content" \
    --argjson ttl "${TTL}" \
    --argjson proxied "$( [ "$PROXIED" = "true" ] && echo true || echo false )" \
    '{type:$type,name:$name,content:$content,ttl:$ttl,proxied:$proxied}')"
  resp="$(cf_api PUT "/zones/${zid}/dns_records/${rid}" "$data" 2>/dev/null)" || return 1
  ok="$(echo "$resp" | jq -r '.success')"
  [ "$ok" = "true" ]
}

ddns_update_one() {
  # args: TYPE IP
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
# Telegram test (manual)
# -------------------------
cf_ready_for_query() {
  # return 0 if CF config looks complete enough to query current record
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
    a_local="$(get_ipv4)"; [ -z "$a_local" ] && a_local="(get ipv4 fail)"
  fi
  if [ "${ENABLE_IPV6:-0}" = "1" ]; then
    v6_local="$(get_ipv6)"; [ -z "$v6_local" ] && v6_local="(get ipv6 fail)"
  fi

  a_cf="(skip)"
  v6_cf="(skip)"
  if cf_ready_for_query; then
    # try query CF current record values, but do not fail the test if CF query fails
    local zid infoA infoAAAA
    zid="$(get_zone_id 2>/dev/null || true)"
    if [ -n "$zid" ]; then
      if [ "${ENABLE_IPV4:-1}" = "1" ]; then
        infoA="$(get_record_info "$zid" "A" "$CFRECORD_NAME" 2>/dev/null || true)"
        a_cf="${infoA#*|}"; [ -z "$a_cf" ] && a_cf="(none)"
      fi
      if [ "${ENABLE_IPV6:-0}" = "1" ]; then
        infoAAAA="$(get_record_info "$zid" "AAAA" "$CFRECORD_NAME" 2>/dev/null || true)"
        v6_cf="${infoAAAA#*|}"; [ -z "$v6_cf" ] && v6_cf="(none)"
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
# Cron install/uninstall
# -------------------------
cron_line() {
  local script_path
  script_path="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
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
    # Alpine common: /etc/crontabs/root
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
  say "失败日志：$BASE_DIR/${FAIL_LOG_PREFIX}_YYYY-MM-DD.log（北京时间，每天一个，保留${FAIL_KEEP_DAYS}天）"
  say "变更日志：$CHANGE_LOG_FILE（仅IP变更追加，保留近${CHANGE_KEEP_DAYS}天记录）"
}

usage() {
  cat <<EOF
用法：
  bash ddns.sh                      # 交互菜单（配置/执行/cron/telegram）
  bash ddns.sh --run                # 执行一次 DDNS
  bash ddns.sh --install-deps       # 安装依赖（curl/jq/cron/bash）
  bash ddns.sh --install-cron       # 安装每1分钟执行的 cron
  bash ddns.sh --uninstall-cron     # 移除 cron
  bash ddns.sh --tg-config          # Telegram 独立交互配置（不影响CF配置）
  bash ddns.sh --telegram-test      # 手动发送 Telegram 测试通知
  bash ddns.sh --show-paths         # 显示配置/日志路径
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
  -h|--help ) usage ;;
  * ) usage; exit 1 ;;
esac
