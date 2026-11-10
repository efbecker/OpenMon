import os

import pytest

from openmon import ldapauth, vault


@pytest.fixture()
def key(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    yield path
    vault.reset()


def test_vault_roundtrip_and_aad_binding(key):
    nonce, ct = vault.encrypt("id-1", "ldap_bind", "segredo")
    assert len(nonce) == 12 and b"segredo" not in ct
    assert vault.decrypt("id-1", "ldap_bind", nonce, ct) == "segredo"
    for cid, kind in (("id-2", "ldap_bind"), ("id-1", "vmware")):
        with pytest.raises(vault.VaultError):
            vault.decrypt(cid, kind, nonce, ct)


def test_vault_wrong_key_is_detected(key):
    nonce, ct = vault.encrypt("id-1", "ldap_bind", "segredo")
    check = vault.key_check()
    key.write_bytes(os.urandom(32))
    vault.reset()
    assert vault.key_check() != check
    with pytest.raises(vault.VaultError):
        vault.decrypt("id-1", "ldap_bind", nonce, ct)


def test_vault_missing_or_short_key(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(tmp_path / "nao-existe"))
    vault.reset()
    with pytest.raises(vault.VaultError, match="indisponível"):
        vault.master_key()
    (tmp_path / "curta").write_bytes(b"x" * 16)
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(tmp_path / "curta"))
    vault.reset()
    with pytest.raises(vault.VaultError, match="32 bytes"):
        vault.master_key()
    vault.reset()


MAPS = [
    {"group_dn": "CN=NOC,OU=Grupos,DC=corp,DC=local", "role": "operator", "tenant_id": None},
    {"group_dn": "CN=Admins OpenMon,OU=Grupos,DC=corp,DC=local", "role": "global_admin", "tenant_id": None},
    {"group_dn": "CN=Cliente ACME,OU=Grupos,DC=corp,DC=local", "role": "client", "tenant_id": 2},
    {"group_dn": "CN=Cliente Beta,OU=Grupos,DC=corp,DC=local", "role": "client", "tenant_id": 3},
    {"group_dn": "CN=Cliente Gama,OU=Grupos,DC=corp,DC=local", "role": "client", "tenant_id": 4,
     "tenant_active": False},
]


@pytest.mark.parametrize("groups, expected", [
    ([], None),
    (["cn=outro,dc=corp,dc=local"], None),
    (["cn=noc, ou=grupos, dc=corp, dc=local"], ("operator", [])),
    (["CN=NOC,OU=Grupos,DC=corp,DC=local", "CN=Admins OpenMon,OU=Grupos,DC=corp,DC=local"], ("global_admin", [])),
    (["CN=Cliente Beta,OU=Grupos,DC=corp,DC=local", "CN=Cliente ACME,OU=Grupos,DC=corp,DC=local"], ("client", [2, 3])),
    (["CN=Cliente ACME,OU=Grupos,DC=corp,DC=local", "CN=NOC,OU=Grupos,DC=corp,DC=local"], ("operator", [])),
    (["CN=Cliente Gama,OU=Grupos,DC=corp,DC=local"], None),  # tenant desativado
])
def test_resolve_access(groups, expected):
    assert ldapauth.resolve_access(MAPS, groups) == expected


def test_ldap_rejects_plain_ldap_and_empty_password():
    d = ldapauth.Directory(urls=["ldap://dc1.corp.local"], security="ldaps", base_dn="dc=corp,dc=local",
                           bind_dn="svc", bind_password="x")
    with pytest.raises(ldapauth.LdapError, match="ldaps://"):
        ldapauth.connect(d, "svc", "x")
    with pytest.raises(ldapauth.LdapAuthFailed):
        ldapauth.authenticate(d, "joao", "")
