"""Séries por período de um ativo (gráficos das VMs): camada certa, filtro de métricas e isolamento de tenant."""
from datetime import datetime, timedelta, timezone

from openmon.api.assets import choose_tier

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def test_choose_tier_by_span_and_age():
    assert choose_tier(NOW - timedelta(hours=1), NOW, NOW) == ("raw", 60)
    assert choose_tier(NOW - timedelta(hours=24), NOW, NOW) == ("raw", 300)
    assert choose_tier(NOW - timedelta(days=2), NOW, NOW) == ("raw", 900)
    assert choose_tier(NOW - timedelta(days=7), NOW, NOW) == ("hourly", 3600)
    assert choose_tier(NOW - timedelta(days=30), NOW, NOW) == ("hourly", 3 * 3600)
    assert choose_tier(NOW - timedelta(days=90), NOW, NOW) == ("hourly", 6 * 3600)
    assert choose_tier(NOW - timedelta(days=365), NOW, NOW) == ("daily", 86400)
    assert choose_tier(NOW - timedelta(days=1825), NOW, NOW) == ("daily", 7 * 86400)
    # Um dia de 2 meses atrás: o bruto já foi apagado (35 dias), vai para a horária
    old = NOW - timedelta(days=60)
    assert choose_tier(old, old + timedelta(days=1), NOW) == ("hourly", 3600)


def _asset(tenant_id, name):
    return sql("INSERT INTO assets (tenant_id, asset_type, name, attributes) VALUES (%s, 'vm', %s, "
               "'{\"vcpu\": 4, \"memory_bytes\": 8589934592}') RETURNING id", tenant_id, name)[0][0]


@requires_pg
def test_vm_series_respect_tenant(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf, "acme", "ACME S.A.")
    beta = new_tenant(client, csrf, "beta", "Beta Ltda")
    vm_a = _asset(acme["id"], "acme-app01")
    vm_b = _asset(beta["id"], "beta-erp")
    # 3 horas de amostras por minuto: CPU sobe de 0 a 179 %... (só para conferir média/mín/máx), rede constante
    sql("""INSERT INTO metric_samples (time, tenant_id, asset_id, metric_id, value)
           SELECT now() - make_interval(mins => g), %s, %s, 1, 179 - g FROM generate_series(0, 179) g
           UNION ALL
           SELECT now() - make_interval(mins => g), %s, %s, 30, 1e6 FROM generate_series(0, 179) g
           UNION ALL
           SELECT now() - make_interval(mins => g), %s, %s, 1, 50 FROM generate_series(0, 179) g""",
        acme["id"], vm_a, acme["id"], vm_a, beta["id"], vm_b)

    r = client.get(f"/api/assets/{vm_a}/metrics?period=6h").json()
    assert r["tier"] == "raw" and r["bucket_seconds"] == 60
    assert r["asset"]["vcpu"] == 4 and r["asset"]["tenant_name"] == "ACME S.A."
    by_key = {s["key"]: s for s in r["series"]}
    assert set(by_key) == {"cpu.usage.pct", "net.rx.bps"}
    cpu = by_key["cpu.usage.pct"]
    assert cpu["unit"] == "%" and len(cpu["points"]) in (180, 181)
    assert cpu["stats"]["min"] == 0 and cpu["stats"]["max"] == 179 and cpu["stats"]["last"] == 179
    assert cpu["points"] == sorted(cpu["points"])

    only = client.get(f"/api/assets/{vm_a}/metrics?period=24h&keys=net.rx.bps").json()
    assert [s["key"] for s in only["series"]] == ["net.rx.bps"] and only["bucket_seconds"] == 300
    assert only["series"][0]["stats"]["avg"] == 1e6

    # Camada horária (agregado em tempo real) para 7 dias
    week = client.get(f"/api/assets/{vm_a}/metrics?period=7d&keys=cpu.usage.pct").json()
    assert week["tier"] == "hourly" and week["series"][0]["stats"]["max"] == 179

    frm = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    custom = client.get(f"/api/assets/{vm_a}/metrics", params={"from": frm, "keys": "cpu.usage.pct"}).json()
    assert custom["tier"] == "raw" and len(custom["series"][0]["points"]) in (60, 61)

    assert client.get(f"/api/assets/{vm_a}/metrics?period=2w").status_code == 422
    assert client.get(f"/api/assets/{vm_a}/metrics?keys=cpu.nada").status_code == 422
    assert client.get(f"/api/assets/{vm_a}/metrics", params={"from": "ontem"}).status_code == 422

    # Cliente da ACME: vê a própria VM; a da Beta não existe para ele
    new_user(client, csrf, "cli-acme", tenant_ids=[acme["id"]], must_change_password=False)
    login(client, "cli-acme", TEMP_PW)
    assert client.get(f"/api/assets/{vm_a}/metrics?period=1h").json()["series"]
    assert client.get(f"/api/assets/{vm_b}/metrics?period=1h").status_code == 404
    lst = client.get("/api/assets?asset_type=vm").json()["assets"]
    assert [a["name"] for a in lst] == ["acme-app01"] and lst[0]["latest"]["net_rx_bps"] == 1e6
