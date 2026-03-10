# Wazuh Telegram Alerts

Script em **Python** que monitora alertas críticos do **Wazuh** (nível ≥ 12), agrupa por regra, analisa com **IA** (Groq API) e envia **resumos inteligentes diretamente no Telegram**.

Funciona como um serviço **24/7**, evita spam de alertas isolados e ajuda a priorizar incidentes reais.

---

# Funcionalidades

- Verifica alertas em janela configurável (padrão: **últimos 60 minutos**)
- Filtra apenas alertas **nível ≥ 12**
- Envia alerta apenas se a mesma regra ocorrer **≥ 3 vezes**
- Mostra agentes afetados com emoji do sistema  
  - 🐧 Linux  
  - 🪟 Windows  
- **Análise automática com IA**
  - causa provável
  - risco
  - ação recomendada
- Link direto para **Threat Hunting no Wazuh Dashboard**
- Logging completo em:

```
/var/log/wazuh-telegram-resumo.log
```

- Suporte a múltiplos agentes e grupos
- Fuso horário configurado para **America/Fortaleza (-03)**

---

# Pré-requisitos

- Python **3.8 ou superior**
- Acesso ao **Wazuh Indexer (porta 9200)**
- **Bot Telegram** criado
- **Chat ID** do grupo
- Chave **Groq API** ou **OpenAI API**

---

# Instalação

## 1. Clonar repositório

```bash
git clone https://github.com/SEU_USUARIO/wazuh-telegram-alerts.git
cd wazuh-telegram-alerts
```

## 2. Criar ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Instalar dependências

```bash
pip install -r requirements.txt
```

Conteúdo do **requirements.txt**

```
requests
python-telegram-bot
pytz
```

---

# Configuração

Configure as variáveis de ambiente (recomendado via `.env` ou `systemd`):

```bash
export INDEXER_PASSWORD="sua-senha-wazuh"
export GROQ_API_KEY="gsk_..."
```

ou usando OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
```

---

# Testar o script

```bash
python3 wazuh-telegram-resumo.py
```

---

# Rodar como serviço (systemd)

Crie o arquivo de serviço:

```bash
sudo nano /etc/systemd/system/wazuh-telegram-resumo.service
```

Conteúdo:

```ini
[Unit]
Description=Wazuh Telegram Resumo de Alertas com IA
After=network.target

[Service]
User=root
WorkingDirectory=/caminho/para/o/projeto/wazuh-telegram-alerts

Environment="INDEXER_PASSWORD=sua-senha"
Environment="GROQ_API_KEY=gsk_..."

ExecStart=/caminho/para/o/projeto/wazuh-telegram-alerts/venv/bin/python3 wazuh-telegram-resumo.py

Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

---

# Ativar o serviço

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-telegram-resumo.service
sudo systemctl start wazuh-telegram-resumo.service
sudo systemctl status wazuh-telegram-resumo.service
```

---

# Configurações principais

Editáveis diretamente no script:

```python
WINDOW_MIN      = 60      # janela de análise em minutos
MIN_LEVEL       = 12      # nível mínimo de alerta
MIN_COUNT       = 3       # mínimo de ocorrências da regra para enviar
HIGH_VOLUME     = 100     # limite para destacar "ALTO VOLUME"
MAX_AGENTS_SHOW = 5       # máximo de agentes exibidos
MAX_EVENTS_IA   = 5       # máximo de eventos enviados para análise IA
```

---

# Exemplo de mensagem no Telegram

```
🚨🔥 AVISO: ANTIGEN – ALERTA CRÍTICO NÍVEL >= 16 🔥🚨

⏰ Período: 09/03 21:36 → 22:36 | Nível ≥ 16

🖥️ Agentes Afetados:
   - SRV-VEEAM-B (sem grupo) 💻 (44x)

🆔 Rule ID: 900401
📊 Total de alertas: 44

📝 Descrição:
[ANTIGEN] [Administrador] access detected...

🤖 Análise IA:
Parece autenticações NTLM repetidas no Veeam.
Risco alto. Possível causa: job legítimo ou tentativa de login.

Ação recomendada:
verificar logs de autenticação.

🔗 Ver no Threat Hunting

🕒 Atualizado em 09/03 21:45:30
```

---

# Contribuições

Sinta-se à vontade para abrir **issues** ou enviar **pull requests**.

---

# Licença

MIT License – use, modifique e distribua livremente.

---

Feito com 💙 por **Junior Alvin**  
Fortaleza – Brasil 🇧🇷  
2026
