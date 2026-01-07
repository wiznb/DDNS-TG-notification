```
wget https://raw.githubusercontent.com/wiznb/DDNS-TG-notification/refs/heads/main/ddns.sh && chmod +x /root/ddns.sh && bash ddns.sh
```



✅ 失败日志：/root/ddns/run_YYYY-MM-DD.log（北京时间、每天一个、只记失败、最多保留 3 天，第 4 天删最早）

✅ IP 变更才记：/root/ddns/chip.log（单文件；只在创建/更新成功时记录；自动仅保留近 30 天记录）

✅ 交互可选：仅 IPv4 / 仅 IPv6 / 两者

✅ Telegram：

每次变更成功（A/AAAA 创建/更新）发一次 TG 通知（含 Record name + 当前IP）

TG 配置独立交互：bash ddns.sh --tg-config

手动测试通知：bash ddns.sh --telegram-test

✅ cron 最小 1 分钟：bash ddns.sh --install-cron

✅ 配置/日志全部在 /root/ddns/，脚本本体可放任意路径

1）保存脚本并赋权：

chmod +x /root/ddns.sh


2）先做 Cloudflare/DDNS 配置（v4/v6 模式就在这里选）：

bash /root/ddns.sh


3）单独配置 Telegram（你要的独立交互）：

bash /root/ddns.sh --tg-config


配置完成会自动发一条测试通知。

4）手动再测一次（随时用来排查）：

bash /root/ddns.sh --telegram-test


5）安装 1 分钟 cron：

bash /root/ddns.sh --install-cron
