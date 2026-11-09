import re

from openmon.db import migrations


def test_discover_order_and_names():
    found = migrations.discover()
    assert [m.version[:4] for m in found] == sorted(m.version[:4] for m in found)
    assert found[0].version.startswith("0001_")


def test_wrapped_is_transactional_and_records_version():
    mig = migrations.discover()[0]
    sql = mig.wrapped()
    assert sql.index("BEGIN;") < sql.index("SET LOCAL ROLE openmon_owner;") < sql.index("COMMIT;")
    assert f"VALUES ('{mig.version}', '{mig.checksum}')" in sql


def test_no_hardcoded_secrets_or_default_admin():
    for mig in migrations.discover():
        text = mig.sql.lower()
        assert "admin123" not in text and "password '" not in text
        assert not re.search(r"insert into users", text)


def test_hypertables_have_retention():
    text = "\n".join(m.sql for m in migrations.discover())
    hypertables = re.findall(r"create_hypertable\('(\w+)'", text)
    for name in hypertables:
        assert f"add_retention_policy('{name}'" in text, name
    caggs = re.findall(r"CREATE MATERIALIZED VIEW (\w+)", text)
    for name in caggs:
        assert f"add_retention_policy('{name}'" in text, name
        assert f"add_continuous_aggregate_policy('{name}'" in text, name
