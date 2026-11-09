"""Tuning do PostgreSQL + TimescaleDB a partir do hardware detectado via SSH.

Segue os mesmos princípios do ``timescaledb-tune`` (25 % da RAM para
shared_buffers, 75 % de effective_cache_size, workers por CPU), mas é
determinístico e testável, e gera um arquivo próprio em ``conf.d``.
"""
from __future__ import annotations

from dataclasses import dataclass

MB = 1024 * 1024
GB = 1024 * MB


@dataclass(frozen=True)
class Hardware:
    mem_bytes: int
    cpus: int
    rotational: bool = False      # True = HDD; False = SSD/NVMe/desconhecido virtualizado
    disk_bytes: int | None = None  # tamanho do filesystem de /var/lib/postgresql


@dataclass(frozen=True)
class TuningProfile:
    max_connections: int = 150
    timescale_background_workers: int = 16


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _fmt_mb(value_mb: int) -> str:
    if value_mb >= 1024 and value_mb % 1024 == 0:
        return f"{value_mb // 1024}GB"
    return f"{value_mb}MB"


def compute(hw: Hardware, profile: TuningProfile = TuningProfile()) -> dict[str, str]:
    if hw.mem_bytes < 512 * MB:
        raise ValueError("memória insuficiente para PostgreSQL + TimescaleDB (mínimo 512 MB)")
    if hw.cpus < 1:
        raise ValueError("número de CPUs inválido")

    mem_mb = hw.mem_bytes // MB
    cpus = hw.cpus

    shared_buffers = _clamp(mem_mb // 4, 128, 32 * 1024)
    effective_cache = max(mem_mb * 3 // 4, shared_buffers)
    maintenance = _clamp(mem_mb // 20, 64, 2 * 1024)
    per_gather = _clamp(cpus // 2, 1, 4)
    parallel_maint = _clamp(cpus // 2, 1, 4)
    work_mem = _clamp((mem_mb - shared_buffers) // (profile.max_connections * 3) // per_gather, 4, 256)
    ts_workers = max(profile.timescale_background_workers, 8)
    max_worker_processes = ts_workers + cpus + 3

    if hw.disk_bytes:
        max_wal = _clamp(int(hw.disk_bytes * 0.05) // MB, 2 * 1024, 16 * 1024)
    else:
        max_wal = 4 * 1024
    # Arredonda para GB quando possível (fica legível no arquivo)
    if max_wal >= 1024:
        max_wal = (max_wal // 1024) * 1024

    settings = {
        "max_connections": str(profile.max_connections),
        "shared_buffers": _fmt_mb(shared_buffers),
        "effective_cache_size": _fmt_mb(effective_cache),
        "maintenance_work_mem": _fmt_mb(maintenance),
        "work_mem": _fmt_mb(work_mem),
        "huge_pages": "try",
        "wal_buffers": "16MB",
        "min_wal_size": "1GB",
        "max_wal_size": _fmt_mb(max_wal),
        "checkpoint_timeout": "15min",
        "checkpoint_completion_target": "0.9",
        "wal_compression": "lz4",
        "max_worker_processes": str(max_worker_processes),
        "max_parallel_workers": str(cpus),
        "max_parallel_workers_per_gather": str(per_gather),
        "max_parallel_maintenance_workers": str(parallel_maint),
        "timescaledb.max_background_workers": str(ts_workers),
        "max_locks_per_transaction": "256",
        "random_page_cost": "4.0" if hw.rotational else "1.1",
        "effective_io_concurrency": "2" if hw.rotational else "256",
        "autovacuum_max_workers": str(_clamp(cpus // 2, 3, 8)),
        "autovacuum_naptime": "10s",
        "jit": "off",
    }
    return settings


def render(hw: Hardware, profile: TuningProfile = TuningProfile()) -> str:
    settings = compute(hw, profile)
    disk = f"{hw.disk_bytes // GB} GB" if hw.disk_bytes else "desconhecido"
    lines = [
        "# OpenMon - tuning gerado automaticamente pelo deploy do banco. Não edite:",
        "# o arquivo é sobrescrito a cada deploy. Para ajustes manuais use 99-local.conf.",
        f"# Hardware detectado: {hw.mem_bytes // MB} MB RAM, {hw.cpus} vCPU, "
        f"disco {'HDD' if hw.rotational else 'SSD/NVMe'}, {disk}",
        "",
    ]
    width = max(len(k) for k in settings)
    for key, value in settings.items():
        quoted = value if value.replace(".", "", 1).isdigit() else f"'{value}'"
        lines.append(f"{key.ljust(width)} = {quoted}")
    return "\n".join(lines) + "\n"
