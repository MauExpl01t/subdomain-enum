import pytest

from subdomainenum.bruteforce import load_wordlist
from subdomainenum.models import Severity
from subdomainenum.report import to_html, to_json, to_text
from subdomainenum.scanner import scan


def by_host(result, host):
    return next((s for s in result.subdomains if s.host == host), None)


def test_bundled_wordlist_is_well_formed():
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "common.txt")
    words = load_wordlist(path)
    assert len(words) > 50
    assert "www" in words and "admin" in words
    assert all(w == w.strip() and w for w in words)


# ---------- descubrimiento pasivo (crt.sh) ----------
def test_passive_discovery_without_active(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    assert by_host(result, "www.ejemplo.cl") is not None
    assert by_host(result, "api.ejemplo.cl") is not None
    assert by_host(result, "old-pages.ejemplo.cl") is not None
    assert by_host(result, "fallback.ejemplo.cl") is not None
    # admin.ejemplo.cl solo existe por fuerza bruta: sin --active no debe aparecer
    assert by_host(result, "admin.ejemplo.cl") is None


def test_passive_subdomain_source_is_tagged(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    assert by_host(result, "www.ejemplo.cl").source == "pasiva"


# ---------- liveness: título, servidor, fallback de esquema ----------
def test_live_host_captures_title_and_server(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    www = by_host(result, "www.ejemplo.cl")
    assert www.alive is True
    assert www.scheme == "https"
    assert www.status == 200
    assert www.title == "Bienvenido"
    assert www.server == "nginx"


def test_https_failure_falls_back_to_http(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    fb = by_host(result, "fallback.ejemplo.cl")
    assert fb.alive is True
    assert fb.scheme == "http"
    assert fb.title == "Solo HTTP"


# ---------- fuerza bruta (opt-in) ----------
def test_active_brute_force_finds_extra_host(wordlist_file):
    wl = wordlist_file(["admin", "doesnotexist"])
    result = scan("ejemplo.cl", active=True, wordlist_path=wl)
    admin = by_host(result, "admin.ejemplo.cl")
    assert admin is not None
    assert admin.source == "fuerza_bruta"
    assert admin.alive is True
    # el nombre que no existe en el DNS falso no debe aparecer en el resultado
    assert by_host(result, "doesnotexist.ejemplo.cl") is None


# ---------- DNS comodín: detección y filtrado ----------
def test_wildcard_detected_and_reported(wordlist_file):
    wl = wordlist_file(["api", "dev"])
    result = scan("comodin.cl", active=True, wordlist_path=wl)
    assert result.wildcard_ips == ["93.184.216.1"]
    finding = next(f for f in result.findings if f.check == "wildcard")
    assert finding.severity == Severity.INFO


def test_wildcard_filters_false_positive_but_keeps_real_host(wordlist_file):
    wl = wordlist_file(["api", "dev"])
    result = scan("comodin.cl", active=True, wordlist_path=wl)
    # api.comodin.cl resuelve a una IP real, distinta del comodín: debe quedar
    assert by_host(result, "api.comodin.cl") is not None
    # dev.comodin.cl solo resuelve por el comodín: debe filtrarse como falso positivo
    assert by_host(result, "dev.comodin.cl") is None


# ---------- subdomain takeover ----------
def test_takeover_detected(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    finding = next(f for f in result.findings if f.check == "takeover")
    assert finding.severity == Severity.CRITICAL
    assert "old-pages.ejemplo.cl" in finding.description
    assert "github.io" in finding.evidence


def test_no_takeover_finding_for_domain_without_dangling_cname(wordlist_file):
    wl = wordlist_file(["api"])
    result = scan("comodin.cl", active=True, wordlist_path=wl)
    assert not any(f.check == "takeover" for f in result.findings)


# ---------- reportes ----------
def test_reports_render_without_error(wordlist_file):
    result = scan("ejemplo.cl", active=False)
    assert "old-pages.ejemplo.cl" in to_json(result)
    text = to_text(result, color=False)
    assert "www.ejemplo.cl" in text
    html = to_html(result)
    assert "<script" not in html.lower()
    assert "Bienvenido" in html


def test_unsafe_domain_is_rejected():
    from subdomainenum.safety import UnsafeTargetError
    with pytest.raises(UnsafeTargetError):
        scan("no es un dominio")
