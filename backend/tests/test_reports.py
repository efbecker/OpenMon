"""Painel do cliente e relatórios (consumo x contratado, crescimento) com o vCloud simulado e RLS de verdade."""
from datetime import datetime, timedelta, timezone

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401
from test_vcd_collector import body, fake  # noqa: F401

pytestmark = requires_pg
GB = 1024 ** 3


def _setup(client):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    pollux = new_tenant(client, csrf, "pollux", "Cliente Pollux")
    acme = new_tenant(client, csrf, "acme", "ACME")
    integ = client.post("/api/admin/integrations", json=body(provider, options={"orgs": ["pollux", "AC*"]}),
                        headers=h(csrf)).json()["integration"]
    client.post("/api/admin/tenant-rules", json={"tenant_id": pollux["id"], "match_field": "folder",
                                                 "pattern": "POLLUX", "priority": 10}, headers=h(csrf))
    assert client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf)).json()["status"] == "ok"
    return csrf, provider, pollux, acme, integ


def test_fixing_vdc_moves_its_vms_and_storage(client, fake):
    csrf, provider, pollux, acme, integ = _setup(client)
    vdc_id = sql("SELECT id FROM assets WHERE name = 'ACME / VDC-ACME'")[0][0]
    assert sql("SELECT count(*) FROM assets WHERE parent_id = %s AND tenant_id = %s", vdc_id, provider)[0][0] == 61  # 60 VMs + perfil Silver
    r = client.put(f"/api/admin/assets/{vdc_id}", json={"tenant_id": acme["id"], "tenant_locked": True},
                   headers=h(csrf))
    assert r.status_code == 200, r.text
    client.post(f"/api/admin/integrations/{integ['id']}/poll", headers=h(csrf))
    by_tenant = dict(sql("SELECT t.slug, count(*) FROM assets a JOIN tenants t ON t.id = a.tenant_id "
                         "WHERE a.asset_type IN ('vm', 'datastore') AND a.deleted_at IS NULL GROUP BY t.slug"))
    assert by_tenant == {"pollux": 201, "acme": 61}
    # Datas de criação: a da VM quando vem, senão a da vApp
    created = dict(sql("SELECT name, attributes ->> 'created_at' FROM assets WHERE name IN ('vm-v1-0', 'vm-v1-10')"))
    assert created["vm-v1-0"].startswith("2022-12-15") and created["vm-v1-10"].startswith("2025-03-05")


def test_client_panel_consumption_and_growth(client, fake):
    csrf, provider, pollux, acme, integ = _setup(client)
    vdc = sql("SELECT id FROM assets WHERE name = 'POLLUX / VDC-POLLUX'")[0][0]
    sp = sql("SELECT id FROM assets WHERE name = 'POLLUX / VDC-POLLUX / Gold'")[0][0]
    vm1, vm2 = (sql("SELECT id FROM assets WHERE name = %s", n)[0][0] for n in ("vm-v1-5", "vm-v1-6"))
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    rows = []
    for i in range(24 * 40):  # 40 dias de histórico, uma leitura por hora; CPU sobe de 20% a ~60%
        t = now - timedelta(hours=i)
        pct = 20 + (24 * 40 - i) / 24
        rows += [(t, pollux["id"], vdc, 1, pct), (t, pollux["id"], vdc, 2, 20000 * pct / 100),
                 (t, pollux["id"], vdc, 11, 48 * GB), (t, pollux["id"], vdc, 12, 64 * GB),
                 (t, pollux["id"], sp, 50, 1024 * GB), (t, pollux["id"], sp, 52, 900 * GB),
                 (t, pollux["id"], vm1, 1, 80.0), (t, pollux["id"], vm2, 1, 10.0)]
    import psycopg
    from pgsupport import admin_dsn
    with psycopg.connect(admin_dsn(), autocommit=True) as c:
        with c.cursor().copy("COPY openmon.metric_samples (time, tenant_id, asset_id, metric_id, value) "
                             "FROM STDIN") as cp:
            for r in rows:
                cp.write_row(r)
    sql("UPDATE assets SET deleted_at = now() - interval '10 days' WHERE name = 'vm-v1-199'")

    new_user(client, csrf, "cli-pollux", tenant_ids=[pollux["id"]], must_change_password=False)
    login(client, "cli-pollux", TEMP_PW)
    scope = client.get("/api/reports/scope").json()
    assert [t["name"] for t in scope["tenants"]] == ["Cliente Pollux"] and scope["default_tenant_id"] == pollux["id"]
    assert client.get(f"/api/reports/overview?tenant_id={acme['id']}").status_code == 404

    ov = client.get("/api/reports/overview").json()
    assert ov["tenant"]["id"] == pollux["id"] and len(ov["vdcs"]) == 1
    d = ov["vdcs"][0]
    assert d["cpu"]["allocated_mhz"] == 20000 and d["memory"]["pct"] == 75.0
    assert d["storage"]["limit_bytes"] == 1024 * GB and round(d["storage"]["pct"]) == 95  # leitura da coleta
    assert ov["totals"]["vms"] == 199 and ov["totals"]["vcpu"] == 398

    # 30 dias: agregação horária; o pico e a média vêm da série
    c30 = client.get("/api/reports/consumption?start=" + (now - timedelta(days=30)).date().isoformat()).json()
    assert c30["tier"] == "hourly" and c30["cpu"]["allocated_last"] == 20000
    assert 55 < c30["cpu"]["pct_stats"]["max"] <= 61 and c30["memory"]["pct_stats"]["avg"] == 75
    assert c30["storage"]["allocated_last"] == 1024 * GB
    assert [v["name"] for v in c30["top_vms"]["cpu"]][:2] == ["vm-v1-5", "vm-v1-6"]
    # 1 dia: amostras brutas; 6 meses: diária
    c1 = client.get("/api/reports/consumption", params={"start": (now - timedelta(days=1)).isoformat()}).json()
    assert c1["tier"] == "samples" and any(v is not None for v in c1["cpu"]["pct"])
    c180 = client.get("/api/reports/consumption?start=" + (now - timedelta(days=180)).date().isoformat()).json()
    assert c180["tier"] == "daily" and any(v is not None for v in c180["memory"]["used"])
    assert client.get("/api/reports/consumption?start=2026-02-01&end=2026-01-01").status_code == 422

    # Crescimento: 10 VMs de 12/2022, depois as vApps de 2023, 2024, 2025 e 2026
    g = client.get("/api/reports/growth?start=2022-01-01").json()
    assert g["labels"][0] == "01/2022" and g["series"]["vms"][11] == 10
    # Começou no período: a variação é contada desde o primeiro mês com VMs
    assert g["kpis_since"] == "12/2022" and g["kpis"]["vms"]["start"] == 10 and g["kpis"]["vms"]["end"] == 199
    by_year = {y["year"]: y for y in g["years"]}
    assert by_year[2022]["vms"] == 10 and by_year[2023]["added"]["vms"] == 47
    assert by_year[now.year]["partial_until"] is not None
    assert g["removed"][0]["name"] == "vm-v1-199" and g["estimated_dates"] == 0
    assert g["vms"][0]["created_at"].startswith("2026-02-20")
    g2 = client.get("/api/reports/growth?start=2025-01-01").json()
    assert g2["kpis"]["vms"]["start"] == 104 and g2["kpis"]["vms"]["pct"] == round((199 - 104) / 104 * 100, 1)

    # Administrador escolhe o cliente
    login(client)
    assert client.get("/api/reports/overview").status_code == 422
    assert client.get(f"/api/reports/overview?tenant_id={pollux['id']}").json()["totals"]["vms"] == 199
