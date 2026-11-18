from security.dependency_guard import (
    parse_requirement,
    registry_allowed,
    is_internal_name,
    validate_lock,
    hash_ok
)


def test_parse():
    assert parse_requirement('pkg==1.0') == ('pkg', '1.0')

def test_registry():
    assert registry_allowed('pkg', 'internal') is True

def test_internal_public():
    assert registry_allowed('company-utils', 'public') is False

def test_scope():
    assert registry_allowed('@company/pkg', 'internal') is True

def test_lock():
    assert validate_lock({'name': 'pkg', 'resolved': 'https://internal/simple'}) is True

def test_bad_lock():
    assert validate_lock({'name': 'pkg', 'resolved': 'https://pypi.org/simple'}) is False

def test_hash():
    assert hash_ok('sha256:abc', 'sha256:abc') is True

def test_bad_hash():
    assert hash_ok('sha1:abc', 'sha256:abc') is False

def test_missing():
    assert hash_ok(None, 'sha256:abc') is False

def test_internal():
    assert is_internal_name('company-utils') is True

def test_pin():
    assert parse_requirement('pkg==*') == ('pkg', '*')

def test_git():
    assert parse_requirement('git+https://evil/pkg') == (None, None)

def test_local():
    assert parse_requirement('../pkg') == (None, None)

def test_empty():
    assert parse_requirement('') == (None, None)

def test_normalize():
    assert is_internal_name('Company_Utils') is True
