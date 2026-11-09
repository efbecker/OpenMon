import pytest

from openmon.deploy import tuning

GB = tuning.GB


def test_16gb_8cpu_ssd():
    s = tuning.compute(tuning.Hardware(mem_bytes=16 * GB, cpus=8, rotational=False, disk_bytes=500 * GB))
    assert s["shared_buffers"] == "4GB"
    assert s["effective_cache_size"] == "12GB"
    assert s["maintenance_work_mem"] == "819MB"
    assert s["max_parallel_workers_per_gather"] == "4"
    assert s["max_worker_processes"] == str(16 + 8 + 3)
    assert s["random_page_cost"] == "1.1"
    assert s["max_wal_size"] == "16GB"  # 5% de 500 GB = 25 GB, limitado a 16 GB


def test_small_vm_hdd_limits():
    s = tuning.compute(tuning.Hardware(mem_bytes=2 * GB, cpus=1, rotational=True))
    assert s["shared_buffers"] == "512MB"
    assert s["work_mem"] == "4MB"
    assert s["max_parallel_workers_per_gather"] == "1"
    assert s["random_page_cost"] == "4.0"
    assert s["effective_io_concurrency"] == "2"
    assert s["max_wal_size"] == "4GB"


def test_large_host_caps():
    s = tuning.compute(tuning.Hardware(mem_bytes=512 * GB, cpus=64))
    assert s["shared_buffers"] == "32GB"
    assert s["maintenance_work_mem"] == "2GB"
    assert s["work_mem"] == "256MB"
    assert s["autovacuum_max_workers"] == "8"


def test_too_little_memory():
    with pytest.raises(ValueError):
        tuning.compute(tuning.Hardware(mem_bytes=256 * 1024 * 1024, cpus=2))


def test_render_quotes_units():
    text = tuning.render(tuning.Hardware(mem_bytes=8 * GB, cpus=4))
    assert "shared_buffers" in text and "= '2GB'" in text
    assert "max_connections" in text and "= 150" in text
    assert "jit" in text and "'off'" in text
