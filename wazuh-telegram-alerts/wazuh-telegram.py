#!/usr/bin/env python3
# wazuh-telegram-resumo.py - Versão FINAL com link Threat Hunting

import json
import os
import requests
import asyncio
import time
import urllib3
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from telegram import Bot

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Configurações ──────────────────────────────────────────────────────────────
CONFIG_FILE     = "/etc/antigen/telegram.json"
INDEXER_URL     = "https://127.0.0.1:9200"
INDEXER_USER    = "admin"
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD")

if not INDEXER_PASSWORD:
    print("ERRO: Variável INDEXER_PASSWORD não definida!")
    exit(1)

INDEXER_AUTH    = (INDEXER_USER, INDEXER_PASSWORD)
INDEX_PATTERN   = "wazuh-alerts-*"
TELEGRAM_GROUP  = "-5129181441"
DASHBOARD_URL   = "https://wzh.immunity.com.br"

WINDOW_MIN      = 1440
MIN_LEVEL       = 12
MIN_COUNT       = 3
HIGH_VOLUME     = 100
MAX_AGENTS_SHOW = 5

# ─── Carrega token ──────────────────────────────────────────────────────────────
with open(CONFIG_FILE) as f:
    token = json.load(f)["token"]

bot = Bot(token=token)

# ─── Funções ────────────────────────────────────────────────────────────────────
def get_os_emoji(agent_data):
    platform = agent_data.get("os", {}).get("platform", "").lower()
    if "windows" in platform:
        return "🪟"
    if any(x in platform for x in ["linux", "almalinux", "centos", "debian", "rocky", "ubuntu"]):
        return "🐧"
    return "💻"

def get_alerts(since: datetime):
    since_iso = since.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    query = {
        "size": 6000,
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": since_iso}}}, {"range": {"rule.level": {"gte": MIN_LEVEL}}}]}}
    }
    try:
        r = requests.post(f"{INDEXER_URL}/{INDEX_PATTERN}/_search", auth=INDEXER_AUTH, json=query, verify=False, timeout=30)
        r.raise_for_status()
        return [h["_source"] for h in r.json()["hits"]["hits"]]
    except Exception as e:
        print(f"Indexer erro: {e}")
        return []

async def send_alert(msg: str):
    await bot.send_message(TELEGRAM_GROUP, msg, parse_mode="HTML", disable_notification=False)

# ─── Loop principal ─────────────────────────────────────────────────────────────
async def main():
    last = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MIN)
    
    while True:
        now = datetime.now(timezone.utc)
        start = max(last, now - timedelta(minutes=WINDOW_MIN))
        
        alerts = get_alerts(start)
        if not alerts:
            last = now
            time.sleep(60 * WINDOW_MIN)
            continue
        
        groups = defaultdict(list)
        for a in alerts:
            r = a.get("rule", {})
            key = (r.get("id"), r.get("description", "sem desc"))
            groups[key].append(a)
        
        for (rid, desc), events in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
            count = len(events)
            if count < MIN_COUNT:
                continue
            
            # Agentes afetados
            agent_info = Counter()
            for e in events:
                agent = e.get("agent", {})
                name = agent.get("name", "N/D")
                groups_list = agent.get("group", [])
                if isinstance(groups_list, str): groups_list = [groups_list]
                group_str = ", ".join(g for g in groups_list if g) or "sem grupo"
                key = f"{name} ({group_str})"
                agent_info[key] += 1
            
            parts = []
            for agent_key, qty in agent_info.most_common(MAX_AGENTS_SHOW):
                os_emoji = get_os_emoji(events[0])
                parts.append(f"{agent_key} {os_emoji} ({qty}x)")
            agents_str = "\n   - ".join(parts)
            remaining = len(agent_info) - MAX_AGENTS_SHOW
            if remaining > 0:
                agents_str += f"\n   +{remaining} outros"
            
            level = events[0].get("rule", {}).get("level", MIN_LEVEL)
            
            # Link direto pro Threat Hunting (igual ao que você usa)
            link = (
                f"{DASHBOARD_URL}/app/threat-hunting#/overview/"
                f"?tab=general&tabView=events"
                f"&_a=(filters:!(),query:(language:kuery,query:'*{rid}*'))"
                f"&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-{WINDOW_MIN}m,to:now))"
            )
            
            msg = (
                f"<b>🚨🔥 AVISO: ANTIGEN – ALERTA CRÍTICO NÍVEL >= {level} 🔥🚨</b>\n\n"
                f"⏰ <b>Período:</b> {start.strftime('%d/%m %H:%M')} → {now.strftime('%H:%M')} | Nível ≥ {level}\n\n"
                f"🖥️ <b>Agentes Afetados:</b>\n   - {agents_str}\n\n"
                f"🆔 <b>Rule ID:</b> {rid}\n"
                f"📊 <b>Total de alertas:</b> <b>{count}</b> {'⚡ ALTO VOLUME ⚡' if count >= HIGH_VOLUME else ''}\n\n"
                f"📝 <b>Descrição:</b> {desc}\n\n"
                f'🔗 <a href="{link}">Ver no Threat Hunting</a>\n\n'
                f"🕒 Atualizado em {now.strftime('%d/%m %H:%M:%S')}   🚨🚨"
            )
            
            await send_alert(msg)
            print(f"✅ Enviado: Rule {rid} ({count}x)")
        
        last = now
        time.sleep(60 * WINDOW_MIN)

if __name__ == "__main__":
    asyncio.run(main())
