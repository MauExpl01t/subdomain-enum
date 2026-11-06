import pytest

from subdomainenum.cli import main


def test_requires_authorization_flag():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "ejemplo.cl"])
    assert exc.value.code == 2  # argparse: argumento requerido faltante


def test_active_requires_explicit_ack(capsys):
    rc = main(["scan", "ejemplo.cl", "--i-have-authorization", "--active"])
    assert rc == 1
    assert "i-accept-active-risk" in capsys.readouterr().err


def test_passive_scan_runs_end_to_end(capsys):
    rc = main(["scan", "ejemplo.cl", "--i-have-authorization", "--no-color"])
    assert rc == 0
    assert "www.ejemplo.cl" in capsys.readouterr().out
