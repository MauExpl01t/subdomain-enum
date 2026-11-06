import pytest

from subdomainenum.safety import UnsafeTargetError, assert_safe_ips, is_public_ip, normalize_domain


@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False),
    ("169.254.169.254", False), ("192.168.0.1", False), ("::1", False),
])
def test_is_public_ip(ip, expected):
    assert is_public_ip(ip) is expected


@pytest.mark.parametrize("raw,expected", [
    ("virec.cl", "virec.cl"),
    ("https://virec.cl/algo", "virec.cl"),
    ("  Virec.CL  ", "virec.cl"),
    ("sub.virec.cl.", "sub.virec.cl"),
])
def test_normalize_domain_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "no es un dominio", "-virec.cl", "virec.cl-", "solo_una_palabra"])
def test_normalize_domain_rejects(bad):
    with pytest.raises(UnsafeTargetError):
        normalize_domain(bad)


def test_assert_safe_ips_blocks_private_by_default():
    with pytest.raises(UnsafeTargetError):
        assert_safe_ips("interno.virec.cl", ["127.0.0.1"], allow_private=False)


def test_assert_safe_ips_allows_private_when_flagged():
    assert_safe_ips("interno.virec.cl", ["127.0.0.1"], allow_private=True)  # no lanza


def test_assert_safe_ips_allows_public():
    assert_safe_ips("www.virec.cl", ["8.8.8.8"], allow_private=False)  # no lanza
