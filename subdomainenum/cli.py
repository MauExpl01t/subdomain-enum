"""Interfaz de línea de comandos: subdomainenum scan <dominio>"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .report import to_html, to_json, to_text
from .safety import UnsafeTargetError
from .scanner import scan

LEGAL = ("AVISO: analiza únicamente dominios propios o con autorización escrita del responsable. "
         "El uso sin autorización puede ser delito.")
ACTIVE_WARNING = (
    "AVISO: --active hace fuerza bruta por DNS contra el dominio (muchas consultas) y "
    "visita cada subdominio encontrado para ver si está vivo. Úsalo solo contra dominios "
    "propios o con autorización escrita.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="subdomainenum", description="Enumerador de subdominios. " + LEGAL)
    p.add_argument("--version", action="version", version=f"subdomainenum {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Enumera subdominios de un dominio")
    s.add_argument("domain")
    s.add_argument("--i-have-authorization", action="store_true", required=True,
                   help="Confirma que tienes autorización para analizar este dominio (obligatorio)")
    s.add_argument("--active", action="store_true", help="Habilita fuerza bruta por diccionario DNS")
    s.add_argument("--i-accept-active-risk", action="store_true",
                   help="Confirma que entiendes el riesgo de --active (obligatorio junto con --active)")
    s.add_argument("--allow-private", action="store_true", help="Permite subdominios en redes privadas")
    s.add_argument("--wordlist", help="Wordlist propia (por defecto: wordlists/common.txt)")
    s.add_argument("--format", choices=["text", "json", "html"], default="text")
    s.add_argument("-o", "--output", help="Archivo de salida (por defecto stdout)")
    s.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.active and not args.i_accept_active_risk:
        print("--active requiere también --i-accept-active-risk (confirmación obligatoria).", file=sys.stderr)
        print(ACTIVE_WARNING, file=sys.stderr)
        return 1
    if args.active:
        print(ACTIVE_WARNING, file=sys.stderr)

    try:
        result = scan(args.domain, active=args.active, allow_private=args.allow_private,
                      wordlist_path=args.wordlist)
    except UnsafeTargetError as exc:
        print(f"Objetivo rechazado: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = to_text(result, color=not args.no_color and not args.output and sys.stdout.isatty())
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Reporte guardado en {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
