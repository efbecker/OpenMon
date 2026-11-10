#!/usr/bin/env bash
# =============================================================================
# OpenMon - provisionamento do banco de dados na VM 2
# PostgreSQL (repositório oficial PGDG) + TimescaleDB (repositório oficial)
# Homologado para Debian 13 (Trixie) ou superior. Idempotente: pode ser
# executado de novo para atualizar configuração, certificados e schema.
#
# Uso (como root):  bash provision_db.sh /tmp/openmon-deploy.XXXXXXXX
# O diretório contém: params.env, tuning.conf, roles.sql, sql/ (migrations).
# É enviado pelo deployer da VM 1 via SFTP e apagado ao final.
#
# Protocolo de saída lido pelo deployer:
#   ::step::N::TOTAL::descrição     início de etapa
#   ::info::chave::valor            dado para o relatório
#   ::warn::mensagem                aviso não fatal
#   ::error::mensagem               erro fatal
#   ::cert-begin:: ... ::cert-end:: certificado da CA interna (PEM)
#   ::done::                        sucesso
# =============================================================================
set -Eeuo pipefail
umask 077

WORK_DIR="${1:?uso: provision_db.sh <diretório de trabalho>}"
case "$WORK_DIR" in
    /tmp/openmon-deploy.*) ;;
    *) echo "::error::diretório de trabalho inesperado: $WORK_DIR"; exit 2 ;;
esac

cleanup() { rm -rf -- "$WORK_DIR"; }
trap cleanup EXIT
# shellcheck disable=SC2154  # rc é atribuído dentro do próprio trap
trap 'rc=$?; echo "::error::falha na linha $LINENO: $BASH_COMMAND (código $rc)"; exit $rc' ERR

# shellcheck source=/dev/null
. "$WORK_DIR/params.env"
: "${PG_MAJOR:?}" "${DB_NAME:?}" "${DB_PORT:?}" "${OWNER_ROLE:?}" "${APP_ROLE:?}"
: "${ALLOW_CIDR:?}" "${LISTEN_ADDRESSES:?}" "${CERT_SANS:?}" "${CERT_CN:?}" "${PGDG_KEY_FPR:?}"
TIMESCALE_KEY_FPR="${TIMESCALE_KEY_FPR:-}"

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8
export NEEDRESTART_MODE=a

TOTAL_STEPS=8
step() { echo "::step::$1::$TOTAL_STEPS::$2"; }
info() { echo "::info::$1::$2"; }
warn() { echo "::warn::$*"; }
die()  { echo "::error::$*"; exit 1; }

APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o Dpkg::Use-Pty=0)
apt_install() { apt-get install "${APT_OPTS[@]}" --no-install-recommends "$@"; }
has_systemd() { [ -d /run/systemd/system ]; }

PG_ETC="/etc/postgresql/${PG_MAJOR}/main"
TLS_DIR="${PG_ETC}/tls"
psql_su() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -p "$DB_PORT" "$@"; }

# -----------------------------------------------------------------------------
step 1 "Validando sistema operacional (Debian 13+)"
[ "$(id -u)" -eq 0 ] || die "o provisionamento precisa ser executado como root"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = "debian" ] || die "distribuição não suportada: ${ID:-desconhecida} (requer Debian 13 ou superior)"
CODENAME="${VERSION_CODENAME:-}"
if [ -n "${VERSION_ID:-}" ]; then
    [ "${VERSION_ID%%.*}" -ge 13 ] || die "Debian ${VERSION_ID} não suportado (requer 13/Trixie ou superior)"
else
    case "$CODENAME" in
        trixie|forky) ;;
        *) die "versão do Debian não identificada (codinome '${CODENAME}')" ;;
    esac
fi
[ -n "$CODENAME" ] || die "VERSION_CODENAME ausente em /etc/os-release"
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
    amd64|arm64) ;;
    *) die "arquitetura não suportada pelo repositório TimescaleDB: $ARCH" ;;
esac
info os "${PRETTY_NAME:-Debian $CODENAME}"
info arch "$ARCH"

# -----------------------------------------------------------------------------
step 2 "Instalando pacotes base (apt-get não interativo)"
apt-get update -q
apt_install ca-certificates curl gnupg openssl postgresql-common

# -----------------------------------------------------------------------------
step 3 "Configurando repositórios oficiais PostgreSQL (PGDG) e TimescaleDB"
install -d -m 0755 /etc/apt/keyrings
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME

key_fprs() { gpg --batch --show-keys --with-colons "$1" 2>/dev/null | awk -F: '$1 == "fpr" {print $10}'; }

# O postgresql-common do Debian já traz a chave do PGDG (assinada pelo próprio
# Debian); só baixamos se ela não estiver lá. Em ambos os casos a impressão
# digital é conferida.
PGDG_LOCAL_KEY=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
if [ -s "$PGDG_LOCAL_KEY" ]; then
    cp "$PGDG_LOCAL_KEY" "$GNUPGHOME/pgdg.asc"
else
    curl -fsSL --proto '=https' --tlsv1.2 -o "$GNUPGHOME/pgdg.asc" \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc
fi
key_fprs "$GNUPGHOME/pgdg.asc" | grep -qx "$PGDG_KEY_FPR" \
    || die "a chave do repositório PGDG não confere com a impressão digital esperada ($PGDG_KEY_FPR)"
install -m 0644 "$GNUPGHOME/pgdg.asc" /etc/apt/keyrings/pgdg.asc

curl -fsSL --proto '=https' --tlsv1.2 -o "$GNUPGHOME/timescaledb.asc" \
    https://packagecloud.io/timescale/timescaledb/gpgkey
gpg --batch --yes --dearmor -o "$GNUPGHOME/timescaledb.gpg" "$GNUPGHOME/timescaledb.asc"
TS_FPR="$(key_fprs "$GNUPGHOME/timescaledb.gpg" | head -n1)"
if [ -n "$TIMESCALE_KEY_FPR" ]; then
    key_fprs "$GNUPGHOME/timescaledb.gpg" | grep -qx "$TIMESCALE_KEY_FPR" \
        || die "a chave do repositório TimescaleDB não confere ($TIMESCALE_KEY_FPR)"
else
    warn "impressão digital da chave TimescaleDB não fixada; obtida: ${TS_FPR}"
fi
info timescale_key_fpr "$TS_FPR"
install -m 0644 "$GNUPGHOME/timescaledb.gpg" /etc/apt/keyrings/timescaledb.gpg
rm -rf -- "$GNUPGHOME"
unset GNUPGHOME

# Formato deb822 (padrão do Debian 13); repositórios antigos em .list são removidos
rm -f /etc/apt/sources.list.d/pgdg.list /etc/apt/sources.list.d/timescaledb.list
cat > /etc/apt/sources.list.d/pgdg.sources <<EOF
# OpenMon: repositório oficial do PostgreSQL (apt.postgresql.org)
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: ${CODENAME}-pgdg
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/pgdg.asc
EOF
cat > /etc/apt/sources.list.d/timescaledb.sources <<EOF
# OpenMon: repositório oficial do TimescaleDB (packagecloud.io/timescale)
Types: deb
URIs: https://packagecloud.io/timescale/timescaledb/debian/
Suites: ${CODENAME}
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/timescaledb.gpg
EOF
chmod 0644 /etc/apt/sources.list.d/pgdg.sources /etc/apt/sources.list.d/timescaledb.sources
apt-get update -q

# -----------------------------------------------------------------------------
step 4 "Instalando PostgreSQL ${PG_MAJOR} e TimescaleDB"
apt-cache show "timescaledb-2-postgresql-${PG_MAJOR}" >/dev/null 2>&1 \
    || die "pacote timescaledb-2-postgresql-${PG_MAJOR} indisponível para ${CODENAME}/${ARCH}"
apt_install "postgresql-${PG_MAJOR}" "postgresql-client-${PG_MAJOR}" \
    "timescaledb-2-postgresql-${PG_MAJOR}" timescaledb-tools
compgen -G "/usr/lib/postgresql/${PG_MAJOR}/lib/timescaledb*.so" >/dev/null \
    || die "biblioteca do TimescaleDB não encontrada após a instalação"

if ! pg_lsclusters -h | awk -v v="$PG_MAJOR" '$1 == v && $2 == "main" {found=1} END {exit !found}'; then
    pg_createcluster "$PG_MAJOR" main -p "$DB_PORT"
fi
# Outra versão já ocupando a porta desejada?
if pg_lsclusters -h | awk -v v="$PG_MAJOR" -v p="$DB_PORT" '!($1 == v && $2 == "main") && $3 == p {busy=1} END {exit !busy}'; then
    die "a porta ${DB_PORT} já é usada por outro cluster PostgreSQL: $(pg_lsclusters -h | xargs)"
fi
info pg_package "$(dpkg-query -W -f='${Version}' "postgresql-${PG_MAJOR}")"
info timescaledb_package "$(dpkg-query -W -f='${Version}' "timescaledb-2-postgresql-${PG_MAJOR}")"

# -----------------------------------------------------------------------------
step 5 "Gerando certificados TLS (CA interna + certificado do servidor)"
install -d -m 0700 -o postgres -g postgres "$TLS_DIR"
if [ ! -s "$TLS_DIR/ca.crt" ] || [ ! -s "$TLS_DIR/ca.key" ]; then
    openssl req -x509 -new -nodes -sha256 -days 3650 \
        -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
        -subj "/O=OpenMon/CN=OpenMon Database CA $(hostname -s)" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null
    info tls_ca "criada"
fi
chown root:root "$TLS_DIR/ca.key"
chmod 0600 "$TLS_DIR/ca.key"

regen=0
if [ ! -s "$TLS_DIR/server.crt" ] || [ ! -s "$TLS_DIR/server.key" ]; then
    regen=1
elif [ "$(cat "$TLS_DIR/server.sans" 2>/dev/null)" != "$CERT_SANS" ]; then
    regen=1
elif ! openssl x509 -checkend 2592000 -noout -in "$TLS_DIR/server.crt" >/dev/null; then
    regen=1
elif ! openssl verify -CAfile "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt" >/dev/null 2>&1; then
    regen=1
fi
if [ "$regen" -eq 1 ]; then
    openssl req -new -nodes -sha256 \
        -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" \
        -subj "/O=OpenMon/CN=${CERT_CN}" 2>/dev/null
    cat > "$TLS_DIR/server.ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = ${CERT_SANS}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF
    openssl x509 -req -sha256 -days 825 -in "$TLS_DIR/server.csr" \
        -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
        -extfile "$TLS_DIR/server.ext" -out "$TLS_DIR/server.crt" 2>/dev/null
    printf '%s' "$CERT_SANS" > "$TLS_DIR/server.sans"
    rm -f "$TLS_DIR/server.csr" "$TLS_DIR/server.ext"
    info tls_server_cert "emitido para ${CERT_SANS}"
else
    info tls_server_cert "mantido (válido para ${CERT_SANS})"
fi
chown postgres:postgres "$TLS_DIR/server.key" "$TLS_DIR/server.crt" "$TLS_DIR/ca.crt"
chmod 0600 "$TLS_DIR/server.key"
chmod 0644 "$TLS_DIR/server.crt" "$TLS_DIR/ca.crt"
info tls_expires "$(openssl x509 -enddate -noout -in "$TLS_DIR/server.crt" | cut -d= -f2)"
echo "::cert-begin::"
cat "$TLS_DIR/ca.crt"
echo "::cert-end::"

# -----------------------------------------------------------------------------
step 6 "Aplicando postgresql.conf, pg_hba.conf e tuning; reiniciando o PostgreSQL"
PG_CONF="$PG_ETC/postgresql.conf"
PG_HBA="$PG_ETC/pg_hba.conf"
CONF_D="$PG_ETC/conf.d"
[ -f "$PG_CONF" ] && [ -f "$PG_HBA" ] || die "configuração do cluster não encontrada em $PG_ETC"
install -d -m 0755 -o postgres -g postgres "$CONF_D"

BACKUP_SUFFIX=".openmon-$(date +%Y%m%dT%H%M%S)"
cp -a "$PG_CONF" "$PG_CONF$BACKUP_SUFFIX"
cp -a "$PG_HBA" "$PG_HBA$BACKUP_SUFFIX"
for f in 00-openmon.conf 10-openmon-tuning.conf; do
    if [ -f "$CONF_D/$f" ]; then cp -a "$CONF_D/$f" "$CONF_D/$f$BACKUP_SUFFIX"; fi
done

grep -Eq "^[[:space:]]*include_dir[[:space:]]*=[[:space:]]*'conf\.d'" "$PG_CONF" \
    || printf "\n# OpenMon\ninclude_dir = 'conf.d'\n" >> "$PG_CONF"

cat > "$CONF_D/00-openmon.conf" <<EOF
# OpenMon - configuração base gerada pelo deploy (sobrescrita a cada deploy)
listen_addresses = '${LISTEN_ADDRESSES}'
port = ${DB_PORT}

# TLS obrigatório para conexões de rede (pg_hba só aceita hostssl)
ssl = on
ssl_cert_file = '${TLS_DIR}/server.crt'
ssl_key_file = '${TLS_DIR}/server.key'
ssl_min_protocol_version = 'TLSv1.2'
password_encryption = 'scram-sha-256'

# TimescaleDB
shared_preload_libraries = 'timescaledb'
timescaledb.telemetry_level = off

# Logs (journal / /var/log/postgresql)
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d from %h '
log_min_duration_statement = 2000
log_lock_waits = on
log_temp_files = 0
EOF
install -m 0644 -o postgres -g postgres "$WORK_DIR/tuning.conf" "$CONF_D/10-openmon-tuning.conf"
chown postgres:postgres "$CONF_D/00-openmon.conf"
chmod 0644 "$CONF_D/00-openmon.conf"

# pg_hba: bloco gerenciado no topo (primeira regra que casa vence)
HBA_BLOCK="$(cat <<EOF
# BEGIN OPENMON - bloco gerenciado pelo deploy do OpenMon (não edite)
hostssl   ${DB_NAME}  ${APP_ROLE}    ${ALLOW_CIDR}  scram-sha-256
hostssl   ${DB_NAME}  ${OWNER_ROLE}  ${ALLOW_CIDR}  scram-sha-256
hostnossl all         all            0.0.0.0/0      reject
hostnossl all         all            ::/0           reject
# END OPENMON
EOF
)"
{
    printf '%s\n' "$HBA_BLOCK"
    awk '/^# BEGIN OPENMON/ {skip=1; next} /^# END OPENMON/ {skip=0; next} !skip' "$PG_HBA$BACKUP_SUFFIX"
} > "$PG_HBA.new"
chown postgres:postgres "$PG_HBA.new"
chmod 0640 "$PG_HBA.new"
mv -f "$PG_HBA.new" "$PG_HBA"
if grep -Eq '^[[:space:]]*host.*[[:space:]]trust([[:space:]]|$)' "$PG_HBA"; then
    warn "pg_hba.conf contém regras 'trust' de rede fora do bloco do OpenMon; revise-as"
fi

restore_config() {
    warn "restaurando a configuração anterior do PostgreSQL"
    cp -a "$PG_CONF$BACKUP_SUFFIX" "$PG_CONF"
    cp -a "$PG_HBA$BACKUP_SUFFIX" "$PG_HBA"
    for f in 00-openmon.conf 10-openmon-tuning.conf; do
        if [ -f "$CONF_D/$f$BACKUP_SUFFIX" ]; then cp -a "$CONF_D/$f$BACKUP_SUFFIX" "$CONF_D/$f"; else rm -f "$CONF_D/$f"; fi
    done
    pg_ctlcluster "$PG_MAJOR" main restart || true
}

wait_ready() {
    for _ in $(seq 1 30); do
        runuser -u postgres -- pg_isready -q -p "$DB_PORT" && return 0
        sleep 1
    done
    return 1
}

if has_systemd; then
    systemctl enable --quiet "postgresql@${PG_MAJOR}-main" 2>/dev/null || true
fi
if ! pg_ctlcluster "$PG_MAJOR" main restart || ! wait_ready; then
    tail -n 30 "/var/log/postgresql/postgresql-${PG_MAJOR}-main.log" 2>/dev/null || true
    restore_config
    die "o PostgreSQL não subiu com a nova configuração (configuração anterior restaurada)"
fi
HBA_ERRORS="$(psql_su -d postgres -tAc "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")"
[ "$HBA_ERRORS" = "0" ] || { restore_config; die "pg_hba.conf com $HBA_ERRORS erro(s); configuração anterior restaurada"; }
[ "$(psql_su -d postgres -tAc 'SHOW ssl')" = "on" ] || die "TLS não ficou ativo no PostgreSQL"

# -----------------------------------------------------------------------------
step 7 "Criando papéis, banco '${DB_NAME}', extensão TimescaleDB e schema inicial"
psql_su -d postgres < "$WORK_DIR/roles.sql"
psql_su -d postgres -v db="$DB_NAME" -v owner="$OWNER_ROLE" <<'SQL'
SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L LOCALE %L',
              :'db', :'owner', 'UTF8', 'C.UTF-8')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SQL
psql_su -d postgres -v db="$DB_NAME" -v owner="$OWNER_ROLE" -v app="$APP_ROLE" <<'SQL'
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db', :'owner') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I, %I', :'db', :'owner', :'app') \gexec
SQL

psql_su -d "$DB_NAME" < "$WORK_DIR/sql/0000_bootstrap.sql"
applied=0
while read -r version checksum; do
    [[ "$version" =~ ^[0-9]{4}_[a-z0-9_]+$ ]] || die "nome de migration inválido no manifesto: $version"
    current="$(psql_su -d "$DB_NAME" -tA -v v="$version" <<'SQL'
SELECT checksum FROM openmon.schema_migrations WHERE version = :'v'
SQL
)"
    if [ -z "$current" ]; then
        echo "Aplicando migration ${version}..."
        psql_su -d "$DB_NAME" < "$WORK_DIR/sql/${version}.sql"
        applied=$((applied + 1))
    elif [ "$current" != "$checksum" ]; then
        warn "migration ${version} já aplicada com outro checksum (arquivo alterado depois de aplicado)"
    fi
done < "$WORK_DIR/sql/manifest"
info migrations_applied "$applied"

# -----------------------------------------------------------------------------
# O OpenMon não gerencia firewall (o ambiente já fica atrás de um firewall externo;
# o acesso ao PostgreSQL é restrito pelo pg_hba.conf). Remove a tabela que versões
# antigas do deploy criavam, se ainda existir.
if [ -f /etc/nftables.d/openmon-db.nft ] || { command -v nft >/dev/null 2>&1 && nft list table inet openmon_db >/dev/null 2>&1; }; then
    if command -v nft >/dev/null 2>&1; then nft delete table inet openmon_db 2>/dev/null || true; fi
    rm -f /etc/nftables.d/openmon-db.nft
    info firewall "regras nftables antigas do OpenMon removidas"
fi

# -----------------------------------------------------------------------------
step 8 "Validando a instalação"
while IFS='|' read -r key value; do
    if [ -n "$key" ]; then info "$key" "$value"; fi
done < <(psql_su -d "$DB_NAME" -tA <<'SQL'
SELECT 'server_version', current_setting('server_version')
UNION ALL SELECT 'timescaledb_version', extversion FROM pg_extension WHERE extname = 'timescaledb'
UNION ALL SELECT 'ssl', current_setting('ssl')
UNION ALL SELECT 'shared_buffers', current_setting('shared_buffers')
UNION ALL SELECT 'hypertables', count(*)::text FROM timescaledb_information.hypertables WHERE hypertable_schema = 'openmon'
UNION ALL SELECT 'continuous_aggregates', count(*)::text FROM timescaledb_information.continuous_aggregates WHERE view_schema = 'openmon'
UNION ALL SELECT 'background_jobs', count(*)::text FROM timescaledb_information.jobs WHERE hypertable_schema = 'openmon'
UNION ALL SELECT 'schema_version', max(version) FROM openmon.schema_migrations;
SQL
)
[ -n "$(psql_su -d "$DB_NAME" -tAc "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")" ] \
    || die "extensão timescaledb não está ativa no banco ${DB_NAME}"
echo "::done::"
