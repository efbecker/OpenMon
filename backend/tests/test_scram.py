import base64

from openmon.deploy import scram

# Vetor gerado pelo próprio PostgreSQL 17:
#   SET password_encryption = 'scram-sha-256';
#   CREATE ROLE t PASSWORD 'correct horse battery staple';
#   SELECT rolpassword FROM pg_authid WHERE rolname = 't';
PG_VERIFIER = ("SCRAM-SHA-256$4096:7gjbCWWWlG5sdpkzPiXLxQ==$QVIPOShi18spLXdzVKon2XhshChCawwFB5XhFTWrl1I="
               ":hLQIU1lsEvCqqWJ4wjG7qeG54JA/LrIZ6tmHJBegAjk=")


def test_verifier_matches_postgresql():
    salt = base64.b64decode(PG_VERIFIER.split(":")[1].split("$")[0])
    assert scram.scram_sha256_verifier("correct horse battery staple", salt=salt) == PG_VERIFIER


def test_random_salt_and_format():
    a = scram.scram_sha256_verifier("x" * 32)
    b = scram.scram_sha256_verifier("x" * 32)
    assert a != b and a.startswith("SCRAM-SHA-256$4096:")


def test_generate_password():
    pw = scram.generate_password()
    assert len(pw) == 32 and pw.isalnum()
    assert scram.generate_password() != pw
