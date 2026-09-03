# Deploy do AtivoFix (VPS - Ubuntu)

Guia para subir o AtivoFix em producao. Os arquivos prontos ficam em `deploy/`.

## 1. Preparar o servidor (uma vez)
sudo apt update && sudo apt install -y python3-venv python3-pip nginx certbot python3-certbot-nginx

## 2. Enviar o codigo
sudo mkdir -p /opt/ativofix
# envie a pasta do projeto (exceto .venv, db, logs): rsync --exclude '.venv' --exclude '*.sqlite3*' ./ /opt/ativofix/

## 3. Ambiente virtual + dependencias
cd /opt/ativofix/templates
sudo python3 -m venv .venv
sudo ./.venv/bin/pip install -U pip
sudo ./.venv/bin/pip install -r ../requirements-prod.txt

## 4. Variaveis de ambiente (segredos)
sudo cp ../.env.example .env
# preencha TODAS as variaveis: FLASK_ENV=production, PANEL_USER/PANEL_PASS,
# FLASK_SECRET_KEY, AGENT_TOKEN, SMTP_* e PANEL_TENANT_ID
sudo chown -R www-data:www-data /opt/ativofix

> Em producao, sem PANEL_USER/PANEL_PASS o servidor gera credenciais
> aleatorias (visiveis no log do systemd) - sempre defina as suas.

## 5. Systemd (inicia no boot e reinicia se cair)
sudo cp deploy/ativofix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ativofix
sudo systemctl status ativofix
journalctl -u ativofix -f

## 6. Nginx + HTTPS (Let's Encrypt)
sudo cp deploy/nginx-ativofix.conf /etc/nginx/sites-available/ativofix
# troque o server_name pelo seu dominio e aponte o DNS (A record) para o IP da VPS
sudo ln -s /etc/nginx/sites-available/ativofix /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d ativofix.seudominio.com

## 7. Firewall (UFW)
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

## 8. Backup diario (crontab)
0 3 * * *  cp /opt/ativofix/templates/db.sqlite3 /opt/ativofix/backups/db_$(date +%F).sqlite3

## 9. Agente
Aponte o agente para https://ativofix.seudominio.com usando o mesmo AGENT_TOKEN.
