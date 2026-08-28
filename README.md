# InvPro - Sistema de Gestão de Inventário de TI

Sistema completo para gerenciamento de inventário de computadores, com suporte multi-tenant para empresas.

## Funcionalidades

- 🖥️ **Inventário de PCs** — Coleta automática de hardware e software
- 🏢 **Unidades e Locais** — Organização hierárquica por empresa/setor
- 👥 **Controle de Acesso** — Usuários por unidade com permissões
- 📊 **Dashboard** — Métricas em tempo real (CPU, RAM, Disco)
- 📄 **Relatórios** — Exportação em CSV e PDF
- 🔧 **Scripts Remotos** — Execução de scripts .bat nos PCs
- 🏢 **Multi-Tenant** — Várias empresas no mesmo servidor

## Tecnologias

- **Backend:** Python, Flask, SQLite
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Agente:** Python, psutil, wmi

## Instalação

### Pré-requisitos
- Python 3.8+
- pip

### Passos

```bash
# Clonar repositório
git clone https://github.com/SEU-USERNAME/invpro.git
cd invpro

# Criar ambiente virtual
cd templates
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Instalar dependências
pip install flask flask-wtf flask-limiter python-dotenv fpdf2

# Iniciar servidor
python server.py
```

### Acessar

- URL: http://localhost:5000
- Login padrão: `admin` / `admin`

## Estrutura

```
invpro/
├── templates/
│   ├── server.py          # Servidor Flask principal
│   ├── index.html         # Dashboard principal
│   ├── login.html         # Tela de login
│   ├── unidades.html      # Gerenciamento de unidades
│   ├── empresas.html      # Gerenciamento de empresas
│   ├── scripts.html       # Scripts remotos
│   └── ...
├── agente.py              # Agente de coleta de dados
├── requirements.txt       # Dependências do servidor
└── requirements-agent.txt # Dependências do agente
```

## Uso do Agente

O agente coleta informações do PC e envia para o servidor a cada 30 segundos.

```bash
# Instalar dependências do agente
pip install -r requirements-agent.txt

# Executar agente
python agente.py
```

## Licença

© 2026 InvPro. Todos os direitos reservados.
