#!/usr/bin/env bash
# =============================================================================
# OpenMon - instalador da VM 1 (Frontend Web + Motor de Coleta)
# Debian 13 (Trixie) ou superior. Idempotente: rode de novo para atualizar.
#
#   curl -fsSL https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh | sudo bash
#
# Já fazendo o deploy do banco na VM 2 (via SSH, a partir desta VM):
#
#   curl -fsSL .../install.sh | sudo bash -s -- --db-host 10.10.0.20 --db-ssh-user admin
#
# Repositório privado: gere um token de leitura no GitHub e passe-o pelo
# ambiente (nunca na URL):
#
#   curl -fsSL -H "Authorization: Bearer $TOKEN" \
#     https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
#     | sudo GITHUB_TOKEN="$TOKEN" bash
#
# Opções (também aceitas como variáveis de ambiente OPENMON_*):
#   --db-host HOST          IP/DNS da VM 2: faz o deploy do PostgreSQL + TimescaleDB via SSH
#   --db-ssh-user USER      usuário SSH da VM 2 (padrão: root)
#   --db-ssh-port N         porta SSH da VM 2 (padrão: 22)
#   --db-ssh-key ARQ        chave privada SSH (senão, pede a senha)
#   --db-fingerprint FP     impressão digital SSH esperada (SHA256:...), para rodar sem perguntas
#   --ssh-allow CIDR        restringe o SSH da VM 2 a este CIDR (a VM 1 é sempre liberada)
#   --fqdn NOME             nome do site no Apache (padrão: hostname -f)
#   --admin-cidr CIDR       ativa o nftables da VM 1 liberando SSH só para este CIDR
#   --ref REF               branch/tag/commit do GitHub (padrão: main)
#   --skip-db               não perguntar pelo deploy do banco
# =============================================================================
set -Eeuo pipefail
umask 022

REPO="efbecker/OpenMon"
APP_DIR="/opt/openmon"
WEB_DIR="/var/www/openmon/public"
CONF_DIR="/etc/openmon"
STATE_DIR="/var/lib/openmon"
LOG_DIR="/var/log/openmon"
BACKUP_DIR="/var/backups/openmon"

REF="${OPENMON_REF:-main}"
DB_HOST="${OPENMON_DB_HOST:-}"
DB_SSH_USER="${OPENMON_DB_SSH_USER:-root}"
DB_SSH_PORT="${OPENMON_DB_SSH_PORT:-22}"
DB_SSH_KEY="${OPENMON_DB_SSH_KEY:-}"
DB_FINGERPRINT="${OPENMON_DB_FINGERPRINT:-}"
SSH_ALLOW="${OPENMON_SSH_ALLOW:-}"
FQDN="${OPENMON_FQDN:-}"
ADMIN_CIDR="${OPENMON_ADMIN_CIDR:-}"
SKIP_DB="${OPENMON_SKIP_DB:-0}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --db-host) DB_HOST="$2"; shift ;;
        --db-ssh-user) DB_SSH_USER="$2"; shift ;;
        --db-ssh-port) DB_SSH_PORT="$2"; shift ;;
        --db-ssh-key) DB_SSH_KEY="$2"; shift ;;
        --db-fingerprint) DB_FINGERPRINT="$2"; shift ;;
        --ssh-allow) SSH_ALLOW="$2"; shift ;;
        --fqdn) FQDN="$2"; shift ;;
        --admin-cidr) ADMIN_CIDR="$2"; shift ;;
        --ref) REF="$2"; shift ;;
        --skip-db) SKIP_DB=1 ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true; exit 0 ;;
        *) echo "opção desconhecida: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -t 1 ]; then
    C_B='\033[0;34m'; C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_C='\033[0;36m'; C_0='\033[0m'
else
    C_B=''; C_G=''; C_Y=''; C_R=''; C_C=''; C_0=''
fi
step() { echo -e "\n${C_B}==>${C_0} $*"; }
ok()   { echo -e "${C_G}[OK]${C_0} $*"; }
warn() { echo -e "${C_Y}[AVISO]${C_0} $*"; }
die()  { echo -e "${C_R}[ERRO]${C_0} $*" >&2; exit 1; }
trap 'die "falha na linha $LINENO: $BASH_COMMAND"' ERR

# Responde perguntas pelo terminal mesmo com "curl | bash" (stdin é o script)
have_tty() { [ -r /dev/tty ] && [ -w /dev/tty ] && { : < /dev/tty; } 2>/dev/null; }
ask() {  # ask "pergunta" padrão -> imprime a resposta
    local answer=""
    if have_tty; then
        printf '%s ' "$1" > /dev/tty
        IFS= read -r answer < /dev/tty || true
    fi
    printf '%s' "${answer:-$2}"
}

echo -e "${C_C}"
echo "=========================================================================="
echo "   OpenMon - instalação da VM 1 (Frontend Web + Motor de Coleta)"
echo "=========================================================================="
echo -e "${C_0}"

# -----------------------------------------------------------------------------
step "Verificando o sistema"
[ "$(id -u)" -eq 0 ] || die "rode como root: curl ... | sudo bash"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = "debian" ] || die "este instalador é para Debian 13 ou superior (detectado: ${PRETTY_NAME:-?})"
if [ -n "${VERSION_ID:-}" ]; then
    [ "${VERSION_ID%%.*}" -ge 13 ] || die "Debian ${VERSION_ID} não suportado; use o Debian 13 (Trixie) ou superior"
else
    case "${VERSION_CODENAME:-}" in trixie|forky) ;; *) die "versão do Debian não identificada" ;; esac
fi
[ -d /run/systemd/system ] || die "systemd não está ativo neste sistema"
ok "${PRETTY_NAME}"

# -----------------------------------------------------------------------------
step "Instalando pacotes (apt-get não interativo)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
# Essenciais para instalar e fazer o deploy do banco: falta de qualquer um aborta
CORE=(
    ca-certificates curl openssl sudo chrony nftables fail2ban logrotate zstd tar iproute2
    apache2 python3 python3-venv python3-paramiko python3-psycopg postgresql-client
)
# Usados pela API e pelos coletores: instalados se existirem no repositório
APP=(
    python3-fastapi python3-uvicorn python3-pydantic python3-multipart python3-jinja2
    python3-asyncpg python3-cryptography python3-argon2 python3-bcrypt python3-jwt python3-ldap3
    python3-httpx python3-winrm python3-requests-ntlm python3-pyvmomi python3-systemd
    snmp unattended-upgrades
)
apt-get update -q
apt-get install "${APT_OPTS[@]}" --no-install-recommends "${CORE[@]}"
AVAILABLE=()
MISSING=()
for pkg in "${APP[@]}"; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then AVAILABLE+=("$pkg"); else MISSING+=("$pkg"); fi
done
apt-get install "${APT_OPTS[@]}" --no-install-recommends "${AVAILABLE[@]}"
[ ${#MISSING[@]} -eq 0 ] || warn "fora do repositório do Debian (irão para o venv quando os coletores chegarem): ${MISSING[*]}"
ok "pacotes instalados"

# -----------------------------------------------------------------------------
step "Usuário de serviço e diretórios (FHS)"
if ! id openmon >/dev/null 2>&1; then
    adduser --system --group --home "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin openmon >/dev/null
fi
install -d -m 0755 -o root -g root "$APP_DIR" "$APP_DIR/bin" "$WEB_DIR"
install -d -m 0750 -o root -g openmon "$CONF_DIR" "$CONF_DIR/ssh"
install -d -m 0755 -o root -g root "$CONF_DIR/pki"
install -d -m 0750 -o openmon -g openmon "$STATE_DIR" "$STATE_DIR/spool" "$STATE_DIR/reports"
install -d -m 0750 -o openmon -g adm "$LOG_DIR"
install -d -m 0700 -o openmon -g openmon "$BACKUP_DIR"
install -d -m 2750 -o openmon -g www-data /run/openmon
for f in app.log collector.log auth.log; do
    [ -e "$LOG_DIR/$f" ] || install -m 0640 -o openmon -g adm /dev/null "$LOG_DIR/$f"
done
ok "diretórios prontos"

# -----------------------------------------------------------------------------
step "Baixando o OpenMon ($REPO@$REF)"
SRC=""
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [ -n "$SCRIPT_PATH" ] && [ -f "$SCRIPT_PATH" ]; then
    candidate="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
    if [ -d "$candidate/backend/openmon" ] && [ -d "$candidate/packaging" ]; then
        SRC="$candidate"
        echo "usando os arquivos locais em $SRC"
    fi
fi
TMP_DL=""
cleanup() { if [ -n "$TMP_DL" ]; then rm -rf -- "$TMP_DL"; fi; }
trap cleanup EXIT
if [ -z "$SRC" ]; then
    TMP_DL="$(mktemp -d /tmp/openmon-install.XXXXXXXX)"
    CURL_AUTH=()
    [ -n "$GITHUB_TOKEN" ] && CURL_AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    if ! curl -fsSL --proto '=https' --tlsv1.2 "${CURL_AUTH[@]}" -H "Accept: application/vnd.github+json" \
            -o "$TMP_DL/src.tar.gz" "https://api.github.com/repos/${REPO}/tarball/${REF}"; then
        die "não foi possível baixar o código. Repositório privado? Rode com GITHUB_TOKEN=<token de leitura> (veja o cabeçalho deste script)."
    fi
    mkdir "$TMP_DL/src"
    tar -xzf "$TMP_DL/src.tar.gz" -C "$TMP_DL/src" --strip-components=1 --no-same-owner
    SRC="$TMP_DL/src"
fi
[ -d "$SRC/backend/openmon" ] || die "pacote baixado não contém backend/openmon"

VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/backend/openmon/__init__.py")"
COMMIT="$(cd "$SRC" && git rev-parse --short HEAD 2>/dev/null || true)"
[ -n "$COMMIT" ] || COMMIT="$(tar -tzf "${TMP_DL:-/nonexistent}/src.tar.gz" 2>/dev/null | head -n1 | sed -n 's|.*-\([0-9a-f]\{7,\}\)/$|\1|p' || true)"

# Troca o código de forma atômica (configuração e dados ficam em /etc e /var)
rm -rf "$APP_DIR/app.new"
install -d -m 0755 "$APP_DIR/app.new"
cp -r "$SRC/backend/openmon" "$APP_DIR/app.new/"
find "$APP_DIR/app.new" -name '__pycache__' -prune -exec rm -rf {} +
rm -rf "$APP_DIR/app.old"
[ -d "$APP_DIR/app" ] && mv "$APP_DIR/app" "$APP_DIR/app.old"
mv "$APP_DIR/app.new" "$APP_DIR/app"
rm -rf "$APP_DIR/app.old" "$APP_DIR/packaging"
cp -r "$SRC/packaging" "$APP_DIR/packaging"
install -m 0755 "$SRC"/bin/* "$APP_DIR/bin/"
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"
printf '%s %s\n' "${VERSION:-?}" "${COMMIT:-$REF}" > "$APP_DIR/VERSION"
ok "OpenMon ${VERSION:-?} (${COMMIT:-$REF}) em $APP_DIR/app"

# -----------------------------------------------------------------------------
step "Configuração e chave mestra do cofre"
if [ ! -s "$CONF_DIR/master.key" ]; then
    head -c 32 /dev/urandom > "$CONF_DIR/master.key.new"
    chown openmon:openmon "$CONF_DIR/master.key.new"
    chmod 0400 "$CONF_DIR/master.key.new"
    mv "$CONF_DIR/master.key.new" "$CONF_DIR/master.key"
    ok "chave mestra AES-256 criada em $CONF_DIR/master.key (0400). Inclua-a no backup offline!"
else
    chown openmon:openmon "$CONF_DIR/master.key"
    chmod 0400 "$CONF_DIR/master.key"
    ok "chave mestra existente mantida"
fi
if [ ! -f "$CONF_DIR/openmon.conf" ]; then
    cat > "$CONF_DIR/openmon.conf" <<EOF
# OpenMon - configuração geral
[app]
base_url = https://${FQDN:-$(hostname -f 2>/dev/null || hostname)}
master_key_file = ${CONF_DIR}/master.key
database_config = ${CONF_DIR}/database.conf
log_dir = ${LOG_DIR}

[security]
session_cookie_secure = true
EOF
    chown root:openmon "$CONF_DIR/openmon.conf"
    chmod 0640 "$CONF_DIR/openmon.conf"
fi

# -----------------------------------------------------------------------------
step "Apache2 (HTTPS, headers de segurança, proxy para a API)"
FQDN="${FQDN:-$(hostname -f 2>/dev/null || hostname)}"
[[ "$FQDN" =~ ^[A-Za-z0-9.-]+$ ]] || die "FQDN inválido: $FQDN"
PRIMARY_IP="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p')"
if [ ! -s /etc/ssl/private/openmon.key ] || [ ! -s /etc/ssl/certs/openmon.crt ]; then
    SAN="DNS:${FQDN}"
    [ -n "$PRIMARY_IP" ] && SAN="${SAN},IP:${PRIMARY_IP}"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 825 \
        -keyout /etc/ssl/private/openmon.key -out /etc/ssl/certs/openmon.crt \
        -subj "/O=OpenMon/CN=${FQDN}" -addext "subjectAltName=${SAN}" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
    chown root:ssl-cert /etc/ssl/private/openmon.key 2>/dev/null || true
    chmod 0640 /etc/ssl/private/openmon.key
    warn "certificado autoassinado criado para ${SAN}; troque pelo da empresa em /etc/ssl/certs/openmon.crt"
fi
sed "s|^Define OPENMON_FQDN .*|Define OPENMON_FQDN ${FQDN}|" \
    "$APP_DIR/packaging/apache2/openmon.conf" > /etc/apache2/sites-available/openmon.conf
install -m 0644 "$APP_DIR/packaging/apache2/openmon-security.conf" /etc/apache2/conf-available/openmon-security.conf
if [ ! -f "$WEB_DIR/index.html" ]; then
    cat > "$WEB_DIR/index.html" <<'EOF'
<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>OpenMon</title></head>
<body><h1>OpenMon</h1><p>Instalação base concluída. A interface web será publicada nas próximas versões.</p></body></html>
EOF
fi
a2enmod -q ssl headers proxy proxy_http proxy_wstunnel rewrite http2 >/dev/null
a2enconf -q openmon-security >/dev/null
a2dissite -q 000-default >/dev/null 2>&1 || true
a2ensite -q openmon >/dev/null
apache2ctl configtest
systemctl enable --quiet apache2
systemctl reload-or-restart apache2
ok "https://${FQDN}/ ativo"

# -----------------------------------------------------------------------------
step "systemd, logrotate, tmpfiles e Fail2ban"
install -m 0644 "$APP_DIR/packaging/tmpfiles.d/openmon.conf" /etc/tmpfiles.d/openmon.conf
systemd-tmpfiles --create /etc/tmpfiles.d/openmon.conf
install -m 0644 "$APP_DIR/packaging/logrotate/openmon" /etc/logrotate.d/openmon
for unit in "$APP_DIR"/packaging/systemd/*; do
    install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
install -m 0644 "$APP_DIR/packaging/fail2ban/filter.d/openmon-auth.conf" /etc/fail2ban/filter.d/openmon-auth.conf
install -m 0644 "$APP_DIR/packaging/fail2ban/jail.d/openmon.conf" /etc/fail2ban/jail.d/openmon.conf
systemctl enable --quiet fail2ban
systemctl restart fail2ban || warn "o Fail2ban não reiniciou; veja: journalctl -u fail2ban"

# Só ativa os serviços cujos módulos já existem nesta versão
has_module() { PYTHONPATH="$APP_DIR/app" python3 -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('$1') is None)" 2>/dev/null; }
PENDING=()
if has_module openmon.api.main; then systemctl enable --now --quiet openmon-api.service; else PENDING+=(openmon-api); fi
if has_module openmon.scheduler; then systemctl enable --now --quiet openmon-scheduler.service; else PENDING+=(openmon-scheduler); fi
if has_module openmon.collector; then
    for c in vmware hyperv veeam snmp; do systemctl enable --now --quiet "openmon-collector@${c}.service"; done
else
    PENDING+=(openmon-collector@*)
fi
if has_module openmon.backup; then
    systemctl enable --now --quiet openmon-backup.timer openmon-backup-reschedule.path
else
    PENDING+=(openmon-backup.timer)
fi
systemctl enable --quiet openmon.target 2>/dev/null || true
ok "units instaladas em /etc/systemd/system"
[ ${#PENDING[@]} -eq 0 ] || warn "serviços instalados, mas ainda sem código nesta versão (serão ativados ao atualizar): ${PENDING[*]}"

# -----------------------------------------------------------------------------
step "Firewall nftables da VM 1"
if [ -n "$ADMIN_CIDR" ]; then
    [[ "$ADMIN_CIDR" =~ ^[0-9.]+/[0-9]{1,2}$ ]] || die "--admin-cidr deve ser um CIDR IPv4 (ex.: 10.10.0.0/24)"
    install -d -m 0755 /etc/nftables.d
    DB_SET="${DB_HOST:-}"
    {
        sed -e "s|elements = { 10.10.0.0/24 }|elements = { ${ADMIN_CIDR} }|" "$APP_DIR/packaging/nftables/vm1-frontend.nft" |
        if [[ "$DB_SET" =~ ^[0-9.]+$ ]]; then sed "s|elements = { 10.10.0.20 }|elements = { ${DB_SET} }|"; else sed '/set db_v4 {/,/^    }/d; /@db_v4/d'; fi
    } > /etc/nftables.d/openmon-frontend.nft.new
    nft -c -f /etc/nftables.d/openmon-frontend.nft.new || die "regras nftables inválidas"
    mv -f /etc/nftables.d/openmon-frontend.nft.new /etc/nftables.d/openmon-frontend.nft
    grep -q '^include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null \
        || printf '\n# OpenMon\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf
    nft -c -f /etc/nftables.conf || die "/etc/nftables.conf ficou inválido"
    nft -f /etc/nftables.d/openmon-frontend.nft
    systemctl enable --quiet nftables
    ok "entrada: 80/443 para todos, SSH só de ${ADMIN_CIDR}"
else
    warn "firewall da VM 1 não alterado (use --admin-cidr 10.10.0.0/24 para ativar sem risco de perder o SSH)"
fi

# -----------------------------------------------------------------------------
DB_DONE=0
if [ -z "$DB_HOST" ] && [ "$SKIP_DB" != "1" ] && [ ! -s "$CONF_DIR/database.conf" ] && have_tty; then
    DB_HOST="$(ask "IP da VM 2 (banco) para fazer o deploy agora via SSH [Enter para pular]:" "")"
    if [ -n "$DB_HOST" ]; then
        DB_SSH_USER="$(ask "Usuário SSH da VM 2 [$DB_SSH_USER]:" "$DB_SSH_USER")"
    fi
fi
if [ -n "$DB_HOST" ] && [ "$SKIP_DB" != "1" ]; then
    step "Deploy do banco na VM 2 (${DB_SSH_USER}@${DB_HOST}) via SSH"
    DB_IP="$DB_HOST"
    if ! [[ "$DB_IP" =~ ^[0-9.]+$ ]]; then
        DB_IP="$(getent ahostsv4 "$DB_HOST" | awk 'NR==1 {print $1}')"
        [ -n "$DB_IP" ] || die "não foi possível resolver $DB_HOST"
    fi
    FRONTEND_IP="$(ip -o route get "$DB_IP" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p')"
    [ -n "$FRONTEND_IP" ] || die "sem rota desta VM até $DB_IP"
    echo "IP desta VM visto pela VM 2: $FRONTEND_IP"
    DEPLOY_ARGS=(--db-host "$DB_HOST" --ssh-port "$DB_SSH_PORT" --ssh-user "$DB_SSH_USER"
                 --frontend-address "$FRONTEND_IP" --config-dir "$CONF_DIR")
    [ -n "$DB_SSH_KEY" ] && DEPLOY_ARGS+=(--ssh-key "$DB_SSH_KEY")
    [ -n "$DB_FINGERPRINT" ] && DEPLOY_ARGS+=(--fingerprint "$DB_FINGERPRINT")
    [ -n "$SSH_ALLOW" ] && DEPLOY_ARGS+=(--ssh-allow "$SSH_ALLOW")
    have_tty || [ -n "$DB_FINGERPRINT" ] || die "sem terminal para confirmar a chave SSH: passe --db-fingerprint SHA256:..."
    if have_tty; then
        PYTHONPATH="$APP_DIR/app" python3 -m openmon.deploy "${DEPLOY_ARGS[@]}" < /dev/tty || die "deploy do banco falhou (veja as mensagens acima)"
    else
        PYTHONPATH="$APP_DIR/app" python3 -m openmon.deploy "${DEPLOY_ARGS[@]}" < /dev/null || die "deploy do banco falhou (veja as mensagens acima)"
    fi
    DB_DONE=1
fi

# -----------------------------------------------------------------------------
echo -e "\n${C_G}==========================================================================${C_0}"
echo -e "${C_G} OpenMon ${VERSION:-} instalado na VM 1${C_0}"
echo -e "${C_G}==========================================================================${C_0}"
echo -e " Web:        ${C_C}https://${FQDN}/${C_0}  (ou https://${PRIMARY_IP:-<ip>}/)"
echo -e " Código:     $APP_DIR/app   Configuração: $CONF_DIR   Logs: $LOG_DIR"
if [ "$DB_DONE" = "1" ] || [ -s "$CONF_DIR/database.conf" ]; then
    echo -e " Banco:      configurado em $CONF_DIR/database.conf (TLS verify-full)"
else
    echo -e " Banco:      ainda não provisionado. Na VM 2 basta Debian 13 + SSH; depois rode nesta VM:"
    echo -e "             ${C_C}curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | sudo bash -s -- --db-host <IP_DA_VM2> --db-ssh-user <usuario>${C_0}"
fi
echo -e " Atualizar:  rode o mesmo comando curl de novo (configuração e dados são mantidos)."
echo ""
