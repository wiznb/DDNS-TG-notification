#!/usr/bin/env bash
# ipchange Enterprise v6.4.2 notification hotfix
# Minimal patch for an existing v6.4.x installation:
# - Hide IPv4/IPv6 lines when that family has no address at all
# - Hide DDNS A/AAAA status when that family has no current address
# - Add latest 6 IP-change records + Beijing time to change notifications
# - Keep all other monitoring/DDNS/cleanup/doctor/monitor behavior unchanged

set -Eeuo pipefail

TARGET="/usr/local/bin/ipchange"
INSTALLER="/root/ipchange/install.sh"
BASE="/root/ipchange"
BACKUP_DIR="$BASE/backups"
PATCH_VERSION="6.4.2"

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ 请使用 root 运行：sudo bash $0"
        exit 1
    fi
}

say() { printf '%s\n' "$*"; }

need_root

if [ ! -f "$TARGET" ]; then
    say "❌ 未找到已安装主程序：$TARGET"
    say "   本脚本是 v6.4.x 通知升级补丁，请先安装现有 ipchange Enterprise。"
    exit 1
fi

if ! grep -q '^history_write() {' "$TARGET" \
   || ! grep -q '^check_once() {' "$TARGET" \
   || ! grep -q '^test_notify() {' "$TARGET" \
   || ! grep -q '^service_status() {' "$TARGET"; then
    say "❌ 当前 /usr/local/bin/ipchange 结构与 v6.4.x 不匹配，为安全起见不修改。"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true
stamp="$(TZ=Asia/Shanghai date '+%Y%m%d_%H%M%S' 2>/dev/null || date '+%Y%m%d_%H%M%S')"
backup_runtime="$BACKUP_DIR/ipchange.before-v${PATCH_VERSION}.${stamp}"
backup_installer="$BACKUP_DIR/install.before-v${PATCH_VERSION}.${stamp}.sh"

cp -p "$TARGET" "$backup_runtime"
[ -f "$INSTALLER" ] && cp -p "$INSTALLER" "$backup_installer" || true

workdir="$(mktemp -d /tmp/ipchange-v642.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT

cat > "$workdir/history-helper" <<'EOS'
history_recent6_html() {
    local line n=1 a b c d t i4 i6 out="" fam=""

    [ -s "$HISTORY" ] || {
        printf '暂无变化记录'
        return 0
    }

    while IFS= read -r line; do
        [ -n "$line" ] || continue

        a="$(printf '%s\n' "$line" | awk -F'|' '{print $1}')"
        b="$(printf '%s\n' "$line" | awk -F'|' '{print $2}')"
        c="$(printf '%s\n' "$line" | awk -F'|' '{print $3}')"
        d="$(printf '%s\n' "$line" | awk -F'|' '{print $4}')"

        # Current format: epoch|Beijing time|IPv4|IPv6|...
        if printf '%s' "$a" | grep -Eq '^[0-9]{9,}$' && [ -n "$d" ]; then
            t="$b"; i4="$c"; i6="$d"
        else
            # Compatibility with very old IPv4|IPv6|time records.
            i4="$a"; i6="$b"; t="$c"
        fi

        fam=""
        if [ -n "$i4" ] && [ "$i4" != "无" ]; then
            fam="IPv4: <code>$(html "$i4")</code>"
        fi
        if [ -n "$i6" ] && [ "$i6" != "无" ]; then
            if [ -n "$fam" ]; then
                fam="${fam}  IPv6: <code>$(html "$i6")</code>"
            else
                fam="IPv6: <code>$(html "$i6")</code>"
            fi
        fi

        # A history item with neither family adds no useful information.
        [ -n "$fam" ] || continue

        out="${out}
${n}. <code>$(html "$t")</code>
   ${fam}"
        n=$((n + 1))
        [ "$n" -gt 6 ] && break
    done < "$HISTORY"

    if [ -n "$out" ]; then
        printf '%s' "${out#
}"
    else
        printf '暂无有效 IP 变化记录'
    fi
}
EOS

cat > "$workdir/check-once" <<'EOS'
check_once() {
    local raw4="无" raw6="无" cur4 cur6 now epoch first
    local old_epoch old_time old4 old6 oldf4 oldl4 oldf6 oldl6
    local changed4=0 changed6=0 verify
    local g4 f4 l4 g6 f6 l6 og4 of4 ol4 og6 of6 ol6 msg
    local ip_lines="" cf_lines="" recent=""

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

    # Only render a family when that family actually exists in the old or new
    # state. A VPS that has never had IPv6 will no longer show "旧/新 IPv6: 无".
    if [ "$old4" != "无" ] || [ "$cur4" != "无" ]; then
        ip_lines="${ip_lines}
<b>旧 IPv4:</b> $(fmt_ip_geo "$old4" "$of4" "$ol4")
<b>新 IPv4:</b> $(fmt_ip_geo "$cur4" "$f4" "$l4")"
    fi

    if [ "$old6" != "无" ] || [ "$cur6" != "无" ]; then
        ip_lines="${ip_lines}
<b>旧 IPv6:</b> $(fmt_ip_geo "$old6" "$of6" "$ol6")
<b>新 IPv6:</b> $(fmt_ip_geo "$cur6" "$f6" "$l6")"
    fi

    recent="$(history_recent6_html)"

    msg="🚨 <b>VPS IP 变化通知</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>${ip_lines}

<b>北京时间:</b> <code>$now</code>"

    if [ "$MODE" = "ddns" ]; then
        # Same display rule for Cloudflare: only show the record type for a
        # family that currently has a usable address.
        if [ "$cur4" != "无" ]; then
            cf_lines="${cf_lines}
A: <code>$(html "$CF4_STATUS")</code>"
        fi
        if [ "$cur6" != "无" ]; then
            cf_lines="${cf_lines}
AAAA: <code>$(html "$CF6_STATUS")</code>"
        fi
        if [ -n "$cf_lines" ]; then
            msg="${msg}

<b>Cloudflare DDNS:</b>${cf_lines}
记录: <code>$(html "$CF_RECORD_NAME")</code>"
        fi
    fi

    msg="${msg}

<b>最近 6 次变化:</b>
${recent}"

    tg_send "$msg" || true
    printf '%s\n' "$now" > "$LAST_OK"
    log INFO "IP changed $old4/$old6 -> $cur4/$cur6"
}
EOS

cat > "$workdir/test-notify" <<'EOS'
test_notify() {
    local i4="无" i6="无" g4 f4 l4 g6 f6 l6 ip_lines="" cf_lines="" msg
    [ "$ENABLE_IPV4" = "1" ] && i4="$(get4)"
    [ "$ENABLE_IPV6" = "1" ] && i6="$(get6)"
    g4="$(geo_info "$i4")"; f4="${g4%%|*}"; l4="${g4#*|}"
    g6="$(geo_info "$i6")"; f6="${g6%%|*}"; l6="${g6#*|}"

    [ "$MODE" = "ddns" ] && cf_reconcile_all "$i4" "$i6"

    [ "$i4" != "无" ] && ip_lines="${ip_lines}
<b>IPv4:</b> $(fmt_ip_geo "$i4" "$f4" "$l4")"
    [ "$i6" != "无" ] && ip_lines="${ip_lines}
<b>IPv6:</b> $(fmt_ip_geo "$i6" "$f6" "$l6")"

    msg="🧪 <b>ipchange 测试通知</b>

<b>VPS:</b> <code>$(html "$VPS_NAME")</code>
<b>模式:</b> <code>$([ "$MODE" = "ddns" ] && echo 'DDNS + 通知' || echo '仅通知')</code>${ip_lines}
<b>北京时间:</b> <code>$(bj_now)</code>
<b>无结果策略:</b> <code>连续 ${NO_THRESHOLD} 次才确认</code>"

    if [ "$MODE" = "ddns" ]; then
        [ "$i4" != "无" ] && cf_lines="${cf_lines}
<b>DDNS A:</b> <code>$(html "$CF4_STATUS")</code>"
        [ "$i6" != "无" ] && cf_lines="${cf_lines}
<b>DDNS AAAA:</b> <code>$(html "$CF6_STATUS")</code>"
        [ -z "$cf_lines" ] || msg="${msg}${cf_lines}"
    fi

    echo "正在发送 Telegram 测试通知..."
    tg_send "$msg" && echo "✅ Telegram 测试成功。" || {
        echo "❌ Telegram 测试失败，请执行 ipchange logs"
        return 1
    }
}
EOS

patch_one() {
    local file="$1" tmp1 tmp2 tmp3 tmp4
    tmp1="$workdir/1.$$.tmp"
    tmp2="$workdir/2.$$.tmp"
    tmp3="$workdir/3.$$.tmp"
    tmp4="$workdir/4.$$.tmp"

    # 1) Insert/replace recent-history renderer just before the Cloudflare block.
    awk -v helper="$workdir/history-helper" '
        BEGIN {
            while ((getline x < helper) > 0) H = H x ORS
            close(helper)
            skip=0; inserted=0
        }
        /^history_recent6_html\(\) \{/ {
            printf "%s", H
            skip=1; inserted=1
            next
        }
        skip && /^# ---------- Cloudflare/ { skip=0; print; next }
        /^# ---------- Cloudflare/ && !inserted { printf "%s", H; inserted=1; print; next }
        !skip { print }
    ' "$file" > "$tmp1"

    # 2) Replace check_once only; service_status marker is kept intact.
    awk -v repl="$workdir/check-once" '
        BEGIN { while ((getline x < repl) > 0) R=R x ORS; close(repl); skip=0 }
        /^check_once\(\) \{/ { printf "%s", R; skip=1; next }
        skip && /^service_status\(\) \{/ { skip=0; print; next }
        !skip { print }
    ' "$tmp1" > "$tmp2"

    # 3) Replace test_notify only; geo_test_one marker is kept intact.
    awk -v repl="$workdir/test-notify" '
        BEGIN { while ((getline x < repl) > 0) R=R x ORS; close(repl); skip=0 }
        /^test_notify\(\) \{/ { printf "%s", R; skip=1; next }
        skip && /^geo_test_one\(\) \{/ { skip=0; print; next }
        !skip { print }
    ' "$tmp2" > "$tmp3"

    # 4) Version bump only; do not touch any unrelated configuration/logic.
    sed -E \
        -e 's/VERSION="6\.4\.[0-9]+"/VERSION="6.4.2"/g' \
        -e 's/ipchange Enterprise v6\.4\.[0-9]+/ipchange Enterprise v6.4.2/g' \
        "$tmp3" > "$tmp4"

    bash -n "$tmp4"
    chmod --reference="$file" "$tmp4" 2>/dev/null || chmod 755 "$tmp4"
    chown --reference="$file" "$tmp4" 2>/dev/null || true
    cat "$tmp4" > "$file"
}

say "=================================================="
say " ipchange Enterprise v${PATCH_VERSION} 通知升级"
say "=================================================="
say "备份主程序：$backup_runtime"
[ -f "$INSTALLER" ] && say "备份安装器：$backup_installer"
say

if ! patch_one "$TARGET"; then
    say "❌ 主程序补丁失败，正在回滚。"
    cp -p "$backup_runtime" "$TARGET"
    exit 1
fi

if ! grep -q '^history_recent6_html() {' "$TARGET" \
   || ! grep -q '<b>最近 6 次变化:</b>' "$TARGET"; then
    say "❌ 主程序完整性验证失败，正在回滚。"
    cp -p "$backup_runtime" "$TARGET"
    exit 1
fi

# Patch the stored installer as well, otherwise a later `ipchange setup` would
# regenerate the old notification code.
if [ -f "$INSTALLER" ]; then
    if ! patch_one "$INSTALLER"; then
        say "❌ 安装器副本补丁失败，正在回滚主程序与安装器。"
        cp -p "$backup_runtime" "$TARGET"
        cp -p "$backup_installer" "$INSTALLER"
        exit 1
    fi
fi

hash -r 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipchange.service ]; then
    systemctl restart ipchange >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/ipchange ]; then
    rc-service ipchange restart >/dev/null 2>&1 || true
fi

say "✅ 通知升级完成。"
say "✅ 没有 IPv6 的机器不再显示‘旧/新 IPv6: 无’。"
say "✅ DDNS 通知没有 IPv6 时不再显示 AAAA 跳过项。"
say "✅ IP 变化通知底部增加最近 6 次变化 IP + 北京时间。"
say "✅ ipchange test 同样只显示当前实际存在的 IP 协议。"
say "✅ 其它检测/DDNS/清理/monitor/doctor 逻辑未修改。"
say
say "当前版本：$($TARGET version 2>/dev/null || echo v${PATCH_VERSION})"
say "建议测试："
say "  ipchange test"
say "  ipchange status"
