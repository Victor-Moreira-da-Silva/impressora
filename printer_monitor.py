#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Any, Iterable

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        nextCmd,
        getCmd,
    )
except Exception as e:
    print(f"ERRO REAL AO IMPORTAR PYSNMP: {e}")
    getCmd = None
    nextCmd = None

# =========================
# OIDs
# =========================
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_PAGE_TOTAL = "1.3.6.1.2.1.43.10.2.1.4.1.1"
OID_PRINTER_STATUS = "1.3.6.1.2.1.25.3.5.1.1.1"
OID_ALERT_DESCR_PREFIX = "1.3.6.1.2.1.43.18.1.1.8"

# Toner (walk)
OID_TONER_DESC = "1.3.6.1.2.1.43.11.1.1.6"
OID_TONER_LEVEL = "1.3.6.1.2.1.43.11.1.1.9"
OID_TONER_MAX = "1.3.6.1.2.1.43.11.1.1.8"

PORTAS_IMPRESSAO = (9100, 631, 515)

STATUS_MAP = {
    1: "outro",
    2: "desconhecido",
    3: "idle",
    4: "imprimindo",
    5: "aquecendo",
}

# =========================
# MODELO
# =========================
@dataclass
class PrinterInfo:
    ip: str
    nome: str | None = None
    modelo: str | None = None
    folhas_impressas: int | None = None
    status: str | None = None
    toner: list[str] | None = None
    alertas: list[str] | None = None
    erro: str | None = None


# =========================
# REDE
# =========================
def porta_aberta(ip: str, porta: int, timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, porta)) == 0


def host_parece_impressora(ip: str) -> bool:
    return any(porta_aberta(ip, porta) for porta in PORTAS_IMPRESSAO)


# =========================
# SNMP
# =========================
def snmp_get(ip: str, community: str, oid: str) -> Any:
    if getCmd is None:
        raise RuntimeError("SNMP indisponível")

    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=1, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )

    error_indication, error_status, _, var_binds = next(iterator)

    if error_indication:
        raise RuntimeError(str(error_indication))
    if error_status:
        raise RuntimeError(str(error_status))

    if not var_binds:
        return None

    return var_binds[0][1]


def snmp_walk_dict(ip: str, community: str, oid_base: str) -> dict:
    if nextCmd is None:
        raise RuntimeError("SNMP indisponível")

    resultado = {}

    for (error_indication, error_status, _, var_binds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=1, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid_base)),
        lexicographicMode=False,
    ):
        if error_indication:
            break
        if error_status:
            break

        for oid, valor in var_binds:
            oid_str = str(oid)
            idx = oid_str.split(".")[-1]
            resultado[idx] = str(valor)

    return resultado


# =========================
# COLETA
# =========================
def coletar_dados_impressora(ip: str, community: str) -> PrinterInfo:
    info = PrinterInfo(ip=ip, toner=[], alertas=[])

    try:
        # Nome
        nome = snmp_get(ip, community, OID_SYS_NAME)
        if nome:
            info.nome = str(nome)

        # Modelo
        modelo = snmp_get(ip, community, OID_SYS_DESCR)
        if modelo:
            info.modelo = str(modelo)

        # Contador
        folhas = snmp_get(ip, community, OID_PAGE_TOTAL)
        if folhas:
            info.folhas_impressas = int(folhas)

        # Status
        status = snmp_get(ip, community, OID_PRINTER_STATUS)
        if status:
            info.status = STATUS_MAP.get(int(status), str(status))

        # TONER (multi-cartucho)
        desc = snmp_walk_dict(ip, community, OID_TONER_DESC)
        nivel = snmp_walk_dict(ip, community, OID_TONER_LEVEL)
        maximo = snmp_walk_dict(ip, community, OID_TONER_MAX)

        for idx in desc:
            try:
                atual = int(nivel.get(idx, 0))
                maxv = int(maximo.get(idx, 1))
                pct = int((atual / maxv) * 100) if maxv > 0 else 0

                info.toner.append(f"{desc[idx]}: {pct}%")
            except:
                pass

        # Alertas
        alertas = []
        for texto in snmp_walk_dict(ip, community, OID_ALERT_DESCR_PREFIX).values():
            if texto:
                alertas.append(texto)

        info.alertas = alertas

    except Exception as e:
        info.erro = str(e)

    return info


# =========================
# DESCOBERTA
# =========================
def gerar_ips(cidr: str) -> Iterable[str]:
    rede = ipaddress.ip_network(cidr, strict=False)
    for host in rede.hosts():
        yield str(host)


def descobrir_impressoras(cidr: str, community: str, workers: int = 64):
    ips = list(gerar_ips(cidr))
    candidatas = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futuros = {executor.submit(host_parece_impressora, ip): ip for ip in ips}

        for futuro in as_completed(futuros):
            ip = futuros[futuro]
            try:
                if futuro.result():
                    candidatas.append(ip)
            except:
                pass

    resultados = []

    with ThreadPoolExecutor(max_workers=32) as executor:
        futuros = {
            executor.submit(coletar_dados_impressora, ip, community): ip
            for ip in candidatas
        }

        for futuro in as_completed(futuros):
            resultados.append(futuro.result())

    return resultados


# =========================
# OUTPUT
# =========================
def imprimir_relatorio(printers):
    if not printers:
        print("Nenhuma impressora encontrada.")
        return

    for p in printers:
        print("-" * 70)
        print(f"IP: {p.ip}")
        print(f"Nome: {p.nome or 'N/A'}")
        print(f"Modelo: {p.modelo or 'N/A'}")
        print(f"Folhas: {p.folhas_impressas or 'N/A'}")
        print(f"Status: {p.status or 'N/A'}")

        if p.toner:
            print("Toner:")
            for t in p.toner:
                print(f"  - {t}")
        else:
            print("Toner: N/A")

        if p.alertas:
            print("Alertas:")
            for a in p.alertas:
                print(f"  - {a}")
        else:
            print("Alertas: nenhum")

        if p.erro:
            print(f"Erro: {p.erro}")


def salvar_json(printers, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(p) for p in printers], f, indent=2, ensure_ascii=False)


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cidr")
    parser.add_argument("--community", default="public")
    parser.add_argument("--intervalo", type=int, default=0)
    parser.add_argument("--json", dest="json_path", default="")
    args = parser.parse_args()

    while True:
        print(f"\n[{time.strftime('%H:%M:%S')}] Escaneando {args.cidr}...")

        printers = descobrir_impressoras(args.cidr, args.community)
        imprimir_relatorio(printers)

        if args.json_path:
            salvar_json(printers, args.json_path)

        if args.intervalo <= 0:
            break

        time.sleep(args.intervalo)


if __name__ == "__main__":
    main()