from hash import hash, verify


def test_hash():
    password = "test_password_123"
    hashed = hash(password)
    # e.g. $2b$12$8K1p3Y2v4G6H8J0L2N4P6OZQRSTUVWXYZabcdefghijklmnopqrstu

    assert len(hashed) == 60
    assert hashed.startswith("$2b$")

    hashed2 = hash(password)
    # e.g. $2b$12$9M2q4Z3w5H7I9K1M3O5Q7PaRbScTdUeVfWgXhYiZjAkBlCmDnEoFp
    assert hashed != hashed2
    assert len(hashed2) == 60
    assert hashed2.startswith("$2b$")


def test_verify():
    password = "secure_password"
    wrong_password = "wrong_password"

    hashed = hash(password)

    assert verify(password, hashed) is True
    assert verify(wrong_password, hashed) is False

    empty_hash = hash("")
    assert verify("", empty_hash) is True
    assert verify("nonempty", empty_hash) is False