#!/usr/bin/env python3
# wazuh-telegram-resumo.py - Resumo com análise IA (Groq API) + Logging + Horário local

import json
import os
import requests
import asyncio
import time
import urllib3
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from telegram import Bot
from pytz import timezone as pytz_timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Configuração de Logging ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler('/var/log/wazuh-telegram-resumo.log'),
        logging.StreamHandler()  # Mostra no terminal também
    ]
)
logger = logging.getLogger(__name__)

# ─── Fuso horário local (Fortaleza) ─────────────────────────────────────────────
LOCAL_TZ = pytz_timezone('America/Fortaleza')

# ─── Configurações ──────────────────────────────────────────────────────────────
CONFIG_FILE     = "/etc/antigen/telegram.json"
INDEXER_URL     = "https://127.0.0.1:9200"
INDEXER_USER    = "admin"
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD")
GROK_API_KEY    = os.getenv("GROK_API_KEY")

if not INDEXER_PASSWORD:
    logger.error("INDEXER_PASSWORD não definida!")
    exit(1)

if not GROK_API_KEY:
    logger.error("GROK_API_KEY não definida! Configure com sua chave Groq.")
    exit(1)

INDEXER_AUTH    = (INDEXER_USER, INDEXER_PASSWORD)
INDEX_PATTERN   = "wazuh-alerts-*"
TELEGRAM_GROUP  = "-5129181441"
DASHBOARD_URL   = "https://wzh.immunity.com.br"

WINDOW_MIN      = 60
MIN_LEVEL       = 12
MIN_COUNT       = 3
HIGH_VOLUME     = 100
MAX_AGENTS_SHOW = 5
MAX_EVENTS_IA   = 5

# ─── Carrega token Telegram ─────────────────────────────────────────────────────
with open(CONFIG_FILE) as f:
    token = json.load(f)["token"]

bot = Bot(token=token)

# ─── Análise com IA (Groq API) ──────────────────────────────────────────────────
async def analyze_with_ia(events, rid, desc, count, level):
    if count < MIN_COUNT:
        return "Análise IA ignorada (poucos eventos)."
    
    sample = events[:MAX_EVENTS_IA]
    sample_str = "\n".join([
        f"- {e['timestamp']} | Agente: {e.get('agent', {}).get('name', 'N/D')} | Detalhes: {json.dumps(e.get('data', {}), ensure_ascii=False)}"
        for e in sample
    ])
    
    prompt = (
        f"Analise esses alertas Wazuh (rule {rid}, descrição: {desc}, level {level}, total {count} ocorrências):\n"
        f"{sample_str}\n\n"
        "Responda em português, de forma breve e direta (máx 100 palavras): "
        "o que pode estar acontecendo, nível de risco, possível causa e ação recomendada."
    )
    
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROK_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7,
                "max_tokens": 200
            },
            timeout=15
        )
        r.raise_for_status()
        analysis = r.json()["choices"][0]["message"]["content"].strip()
        logger.info(f"Análise IA para rule {rid}: {analysis[:100]}...")
        return analysis
    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP na Groq API (status {r.status_code}): {r.text[:300]}")
        return "Erro na análise IA (verifique chave Groq ou limite de uso)."
    except Exception as e:
        logger.error(f"Erro geral na Groq API: {e}")
        return "Erro na análise IA."

# ─── Funções auxiliares ─────────────────────────────────────────────────────────
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
        logger.error(f"Indexer erro: {e}")
        return []

async def send_alert(msg: str):
    await bot.send_message(TELEGRAM_GROUP, msg, parse_mode="HTML", disable_notification=False)

# ─── Loop principal ─────────────────────────────────────────────────────────────
async def main():
    last = datetime.now(LOCAL_TZ) - timedelta(minutes=WINDOW_MIN)
    
    while True:
        now = datetime.now(LOCAL_TZ)
        start = max(last, now - timedelta(minutes=WINDOW_MIN))
        
        alerts = get_alerts(start)
        if not alerts:
            logger.info("Nenhum alerta encontrado na janela.")
            last = now
            time.sleep(60 * WINDOW_MIN)
            continue
        
        logger.info(f"Total alertas encontrados na janela: {len(alerts)}")
        
        groups = defaultdict(list)
        for a in alerts:
            r = a.get("rule", {})
            key = (r.get("id"), r.get("description", "sem desc"))
            groups[key].append(a)
        
        logger.info(f"Grupos de regras encontrados: {len(groups)}")
        
        for (rid, desc), events in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
            count = len(events)
            if count < MIN_COUNT:
                logger.info(f"Ignorado rule {rid}: {count}x < {MIN_COUNT}")
                continue
            
            ia_analysis = await analyze_with_ia(events, rid, desc, count, MIN_LEVEL)
            
            agent_info = Counter()
            for e in events:
                agent = e.get("agent", {})
                name = agent.get("name", "N/D")
                groups_list = agent.get("group", [])
                if isinstance(groups_list, str):
                    groups_list = [groups_list]
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
                f"🤖 <b>Análise IA:</b> {ia_analysis}\n\n"
                f'<a href="{link}">🔗 Ver no Threat Hunting</a>\n\n'
                f"🕒 Atualizado em {now.strftime('%d/%m %H:%M:%S')}   🚨🚨"
            )
            
            try:
                await send_alert(msg)
                logger.info(f"Enviado com sucesso: Rule {rid} ({count}x) - IA: {ia_analysis[:100]}...")
            except Exception as send_err:
                logger.error(f"Erro ao enviar mensagem Telegram para rule {rid}: {send_err}")
        
        last = now
        time.sleep(60 * WINDOW_MIN)

if __name__ == "__main__":
    asyncio.run(main())
