#!/usr/bin/env bash
# OpenMon - pré-verificação somente leitura da VM 2 (não precisa de root).
# Saída: linhas CHAVE=valor, lidas pelo deployer para validar o SO e calcular o tuning.
set -u
LC_ALL=C

if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
fi
echo "OS_ID=${ID:-unknown}"
echo "OS_VERSION_ID=${VERSION_ID:-}"
echo "OS_CODENAME=${VERSION_CODENAME:-}"
echo "OS_PRETTY=${PRETTY_NAME:-unknown}"
echo "ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)"
echo "KERNEL=$(uname -r)"
echo "HOSTNAME=$(hostname -f 2>/dev/null || hostname)"
echo "IPS=$(hostname -I 2>/dev/null | xargs)"
echo "CPUS=$(nproc 2>/dev/null || echo 1)"
echo "MEM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"

# Disco onde ficarão os dados do PostgreSQL
target=/var/lib/postgresql
[ -d "$target" ] || target=/var/lib
[ -d "$target" ] || target=/
echo "DISK_BYTES=$(df -PB1 "$target" 2>/dev/null | awk 'NR==2 {print $2}')"
echo "DISK_FREE_BYTES=$(df -PB1 "$target" 2>/dev/null | awk 'NR==2 {print $4}')"
src=$(df -P "$target" 2>/dev/null | awk 'NR==2 {print $1}')
rot=""
if [ -n "$src" ] && command -v lsblk >/dev/null 2>&1; then
    # Disco físico por trás da partição/LVM; ROTA=1 => HDD
    pk=$(lsblk -ndo PKNAME "$src" 2>/dev/null | head -n1)
    rot=$(lsblk -ndo ROTA "/dev/${pk:-$(basename "$src")}" 2>/dev/null | head -n1 | tr -d ' ')
fi
echo "ROTATIONAL=${rot:-0}"

if [ "$(id -u)" -eq 0 ]; then
    echo "IS_ROOT=1"
    echo "SUDO=root"
elif command -v sudo >/dev/null 2>&1; then
    echo "IS_ROOT=0"
    if sudo -n true 2>/dev/null; then echo "SUDO=nopasswd"; else echo "SUDO=password"; fi
else
    echo "IS_ROOT=0"
    echo "SUDO=missing"
fi

if command -v pg_lsclusters >/dev/null 2>&1; then
    echo "PG_CLUSTERS=$(pg_lsclusters -h 2>/dev/null | awk '{printf "%s/%s:%s:%s ", $1, $2, $3, $4}' | xargs)"
else
    echo "PG_CLUSTERS="
fi
