# Ambiente de homologação offline do deploy remoto (VM 2 simulada).
#
# Usa a imagem oficial timescale/timescaledb-ha (PostgreSQL 17 + TimescaleDB
# dos repositórios PGDG/Timescale) e acrescenta sshd, sudo e nftables. Como o
# sandbox de CI não alcança os espelhos do Debian, o /etc/os-release é trocado
# pelo do Debian 13 e o apt-get vira um no-op: as etapas 2-4 (apt) não são
# exercitadas aqui; as etapas 1 e 5-9 (TLS, postgresql.conf, pg_hba, papéis,
# banco, TimescaleDB, migrations, nftables e validação) rodam de verdade.
FROM mirror.gcr.io/timescale/timescaledb-ha:pg17
USER root
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
        openssh-server sudo nftables gnupg iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash admin && echo 'admin:Adm1n-E2E-pass' | chpasswd && usermod -aG sudo admin \
    && mkdir -p /run/sshd && ssh-keygen -A
COPY os-release /etc/os-release
COPY shims/ /usr/local/sbin/
RUN chmod 0755 /usr/local/sbin/*
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
