# 🖥 Painel de Inventário e Execução Remota de Scripts

Sistema completo de inventário de computadores com agente Windows e painel web desenvolvido em Flask.

Permite:

- 📋 Inventariar máquinas automaticamente  
- 🏷 Vincular TAG patrimonial  
- 🖥 Visualizar hardware, software e rede  
- 📝 Criar scripts `.bat`  
- 🚀 Executar scripts remotamente  
- 📊 Monitorar status de execução (jobs)  
- 🟢 Ver status online/offline em tempo real  

---

## 🔧 Tecnologias Utilizadas

- Python 3  
- Flask  
- SQLite  
- JavaScript (Vanilla JS)  
- HTML + CSS  
- PyInstaller (empacotamento do agente)  
- Nginx (deploy em produção)  
- Ubuntu Server (VPS)  

---

## 🏗 Arquitetura do Sistema

### 🔹 Servidor (Flask)

- API REST para comunicação com agentes  
- CRUD completo de scripts  
- Sistema de fila de execução (jobs)  
- Interface web administrativa  
- Banco SQLite para persistência  

### 🔹 Agente Windows

- Envia inventário periódico da máquina  
- Recebe jobs pendentes do servidor  
- Executa scripts localmente  
- Retorna stdout, stderr e exit_code  
- Sistema de confirmação local antes da execução  

---

## 📁 Estrutura do Projeto

```
templates/
    detalhe.html
    index.html
    scripts.html
agente.py
server.py
.gitignore
README.md
```

---

## 🚀 Como Rodar Localmente

### 1️⃣ Criar ambiente virtual

```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

### 2️⃣ Instalar dependências

```bash
pip install flask
```

### 3️⃣ Rodar servidor

```bash
python server.py
```

Servidor disponível em:

```
http://localhost:5000
```

---

## 🔐 Segurança

O agente utiliza autenticação via token no header:

```
X-AGENT-TOKEN
```

Recomendado usar variável de ambiente:

Linux:
```bash
export AGENT_TOKEN=seu_token_aqui
```

Windows:
```powershell
setx AGENT_TOKEN "seu_token_aqui"
```

---

## 📌 Funcionalidades Implementadas

✔ Inventário automático de hardware e software  
✔ Monitoramento de status online/offline  
✔ Sistema de alias para identificação amigável  
✔ Execução remota de scripts com controle de jobs  
✔ Histórico completo de execução  
✔ Preview de scripts no painel  
✔ Exclusão de máquinas do inventário  
✔ Atualização automática da interface  

---

## 📊 Fluxo de Execução de Script

1. Administrador cria um script `.bat`  
2. Seleciona o PC no painel  
3. Sistema cria um job com status `queued`  
4. Agente busca jobs pendentes  
5. Job muda para `running`  
6. Script é executado  
7. Resultado retorna ao servidor  
8. Job finaliza como `done` ou `error`  

---

## 📸 Screenshots

<img width="1536" height="1024" alt="ChatGPT Image 20 de fev  de 2026, 11_03_38" src="https://github.com/user-attachments/assets/5f05c3a7-e29b-4d7e-ada3-bbce5e87bf7e" />


Sugestão:
- Tela principal de inventário  
- Tela de criação de scripts  
- Tela de detalhes da máquina  
- Tela com histórico de jobs  

---

## 🎯 Objetivo do Projeto

Projeto desenvolvido para:

- Estudo de comunicação cliente-servidor  
- Automação de administração de TI  
- Demonstração de habilidades em Python e Flask  
- Portfólio profissional na área de Infraestrutura e Desenvolvimento  



## 📄 Licença

Projeto para fins educacionais e demonstração técnica.
