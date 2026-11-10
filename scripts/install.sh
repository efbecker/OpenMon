#!/usr/bin/env bash
# =============================================================================
# OpenMon - instalador da VM 1 (Frontend Web + Motor de Coleta)
# Debian 13 (Trixie) ou superior. Idempotente: rode de novo para atualizar.
#
#   curl -fsSL https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh | sudo bash
#
# O deploy do banco (VM 2) é feito depois, pela interface web
# (https://<VM 1>/), usando o token de instalação mostrado no final.
#
# Repositório privado: gere um token de leitura no GitHub e passe-o pelo
# ambiente (nunca na URL):
#
#   curl -fsSL -H "Authorization: Bearer $TOKEN" \
#     https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
#     | sudo GITHUB_TOKEN="$TOKEN" bash
#
# Opções (também aceitas como variáveis de ambiente OPENMON_*):
#   --fqdn NOME             nome do site no Apache (padrão: hostname -f)
#   --new-setup-token       gera um novo token de instalação (refazer o deploy do banco)
#   --ref REF               branch/tag/commit do GitHub (padrão: main)
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
FQDN="${OPENMON_FQDN:-}"
NEW_SETUP_TOKEN="${OPENMON_NEW_SETUP_TOKEN:-0}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --fqdn) FQDN="$2"; shift ;;
        --ref) REF="$2"; shift ;;
        --new-setup-token) NEW_SETUP_TOKEN=1 ;;
        -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || true; exit 0 ;;
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
    python3-fastapi python3-uvicorn python3-pydantic python3-asyncpg python3-argon2
)
# Usados pela API e pelos coletores: instalados se existirem no repositório
APP=(
    python3-multipart python3-jinja2
    python3-cryptography python3-bcrypt python3-jwt python3-ldap3
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
# Único ponto de /etc gravável pela API (configuração gerada pelo deploy do banco)
install -d -m 0750 -o openmon -g openmon "$CONF_DIR/database"
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
database_config = ${CONF_DIR}/database/database.conf
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
# Interface web (estáticos). __VERSION__ força o navegador a buscar os assets novos.
find "$WEB_DIR" -mindepth 1 -delete
cp -r "$SRC/frontend/public/." "$WEB_DIR/"
sed -i "s/__VERSION__/${COMMIT:-$REF}/g" "$WEB_DIR"/*.html
chown -R root:root "$WEB_DIR"
chmod -R u=rwX,go=rX "$WEB_DIR"
a2enmod -q ssl headers proxy proxy_http proxy_wstunnel rewrite http2 >/dev/null
# ServerName global: evita os avisos AH00557/AH00558 quando o hostname não resolve
echo "ServerName localhost" > /etc/apache2/conf-available/openmon-servername.conf
a2enconf -q openmon-security openmon-servername >/dev/null
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

# Token de instalação: libera o assistente web (deploy do banco + primeiro
# administrador) até a instalação terminar, marcada por $STATE_DIR/setup.done
SETUP_TOKEN=""
[ "$NEW_SETUP_TOKEN" = "1" ] && rm -f "$STATE_DIR/setup.done"
if [ ! -e "$STATE_DIR/setup.done" ]; then
    if [ "$NEW_SETUP_TOKEN" = "1" ] || [ ! -s "$STATE_DIR/setup.token" ]; then
        openssl rand -hex 24 > "$STATE_DIR/setup.token.new"
        chown openmon:openmon "$STATE_DIR/setup.token.new"
        chmod 0600 "$STATE_DIR/setup.token.new"
        mv -f "$STATE_DIR/setup.token.new" "$STATE_DIR/setup.token"
    fi
    SETUP_TOKEN="$(cat "$STATE_DIR/setup.token")"
fi

# Só ativa os serviços cujos módulos já existem nesta versão
has_module() { PYTHONPATH="$APP_DIR/app" python3 -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('$1') is None)" 2>/dev/null; }
PENDING=()
if has_module openmon.api.main; then
    systemctl enable --quiet openmon-api.service
    systemctl restart openmon-api.service
    for _ in $(seq 1 20); do [ -S /run/openmon/api.sock ] && break; sleep 0.5; done
    [ -S /run/openmon/api.sock ] || warn "a API não subiu; veja: journalctl -u openmon-api -n 50"
else
    PENDING+=(openmon-api)
fi
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

# Sem firewall local: o OpenMon fica atrás do firewall do ambiente. Remove as
# regras que versões antigas do instalador podiam ter criado.
if [ -f /etc/nftables.d/openmon-frontend.nft ]; then
    nft delete table inet openmon_frontend 2>/dev/null || true
    rm -f /etc/nftables.d/openmon-frontend.nft
    ok "regras nftables antigas do OpenMon removidas"
fi

# -----------------------------------------------------------------------------
echo -e "\n${C_G}==========================================================================${C_0}"
echo -e "${C_G} OpenMon ${VERSION:-} instalado na VM 1${C_0}"
echo -e "${C_G}==========================================================================${C_0}"
echo -e " Web:        ${C_C}https://${FQDN}/${C_0}  (ou https://${PRIMARY_IP:-<ip>}/)"
echo -e " Código:     $APP_DIR/app   Configuração: $CONF_DIR   Logs: $LOG_DIR"
if [ -z "$SETUP_TOKEN" ]; then
    echo -e " Banco:      provisionado ($CONF_DIR/database/database.conf, TLS verify-full)"
    echo -e " Login:      ${C_C}https://${PRIMARY_IP:-$FQDN}/login.html${C_0}"
elif [ -s "$CONF_DIR/database/database.conf" ]; then
    echo ""
    echo -e " ${C_Y}Próximo passo: criar o administrador pela interface web${C_0}"
    echo -e "   1. Abra ${C_C}https://${PRIMARY_IP:-$FQDN}/${C_0} (certificado autoassinado: aceite o aviso)"
    echo -e "   2. Token de instalação: ${C_G}${SETUP_TOKEN}${C_0}"
    echo -e "      (também em $STATE_DIR/setup.token; vale até o administrador ser criado)"
    echo -e "   3. O banco já está provisionado: o assistente abre direto na criação do administrador."
else
    echo ""
    echo -e " ${C_Y}Próximo passo: deploy do banco (VM 2) pela interface web${C_0}"
    echo -e "   1. Abra ${C_C}https://${PRIMARY_IP:-$FQDN}/${C_0} (certificado autoassinado: aceite o aviso)"
    echo -e "   2. Token de instalação: ${C_G}${SETUP_TOKEN}${C_0}"
    echo -e "      (também em $STATE_DIR/setup.token; vale até o administrador ser criado)"
    echo -e "   3. Na VM 2 basta Debian 13 com SSH e um usuário com sudo."
    echo -e "   4. Depois do deploy, crie o administrador na mesma tela e entre pelo login."
fi
echo -e " Atualizar:  rode o mesmo comando curl de novo (configuração e dados são mantidos)."
echo ""
