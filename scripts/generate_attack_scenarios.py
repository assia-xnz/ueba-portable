"""Génère des CSV synthétiques pour 3 scénarios d'attaque MITRE ATT&CK.

Scénarios générés :
  1. Password Spraying (T1110.003) — 6 comptes, 3 échecs chacun, 5 min, 1 IP
  2. Kerberoasting (T1558.003) — 1 compte, 12 requêtes TGS en rafale
  3. Mouvement latéral (T1021) — 1 compte, 8 hôtes distincts en 20 min

Usage:
    python scripts/generate_attack_scenarios.py --output-dir data/scenarios/
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

BASE_DATE = datetime(2026, 6, 1, 8, 0, 0)

USERS_SPRAY = [
    "user.spray1",
    "user.spray2",
    "user.spray3",
    "user.spray4",
    "user.spray5",
    "user.spray6",
]

USERS_KERB = ["svc.kerb"]
USERS_LATERAL = ["admin.pivot"]

FIELDS = [
    "@timestamp",
    "agent.name",
    "data.win.system.eventID",
    "data.win.eventdata.targetUserName",
    "data.win.eventdata.subjectUserName",
    "data.win.eventdata.logonType",
    "data.win.eventdata.workstationName",
    "data.win.eventdata.ipAddress",
    "data.win.eventdata.processName",
    "data.win.eventdata.parentProcessName",
    "rule.level",
    "rule.mitre.id",
    "rule.mitre.tactic",
]


def _row(
    ts: datetime,
    event_id: int,
    user: str = "",
    logon_type: str = "",
    host: str = "corp-dc01",
    src_ip: str = "",
    process: str = "",
    parent: str = "",
    mitre_id: str = "",
    mitre_tactic: str = "",
    level: int = 5,
) -> dict:  # type: ignore[type-arg]
    return {
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "agent.name": host,
        "data.win.system.eventID": event_id,
        "data.win.eventdata.targetUserName": user,
        "data.win.eventdata.subjectUserName": "",
        "data.win.eventdata.logonType": logon_type,
        "data.win.eventdata.workstationName": host,
        "data.win.eventdata.ipAddress": src_ip,
        "data.win.eventdata.processName": process,
        "data.win.eventdata.parentProcessName": parent,
        "rule.level": level,
        "rule.mitre.id": mitre_id,
        "rule.mitre.tactic": mitre_tactic,
    }


def _write(rows: list[dict], path: Path) -> None:  # type: ignore[type-arg]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Écrit : {path}  ({len(rows)} lignes)")


# ---------------------------------------------------------------------------
# Scénario 1 — Password Spraying (T1110.003)
# ---------------------------------------------------------------------------


def scenario_password_spray(output_dir: Path) -> None:
    """6 comptes × 3 échecs en 5 min depuis 192.168.100.10."""
    rows = []
    attack_start = BASE_DATE.replace(hour=14, minute=0)

    # Activité normale préalable (J-1)
    normal_day = BASE_DATE - timedelta(days=1)
    for i, user in enumerate(USERS_SPRAY):
        for h in [8, 10, 12, 14, 16]:
            rows.append(
                _row(
                    normal_day.replace(hour=h, minute=i * 3),
                    4624,
                    user,
                    "3",
                    "corp-wks0" + str(i + 1),
                    "10.0.1." + str(i + 10),
                )
            )

    # Phase d'attaque : 3 échecs par compte, espacés de ~30s
    for i, user in enumerate(USERS_SPRAY):
        for attempt in range(3):
            ts = attack_start + timedelta(seconds=i * 15 + attempt * 90)
            rows.append(
                _row(
                    ts,
                    4625,
                    user,
                    "3",
                    "corp-dc01",
                    "192.168.100.10",
                    mitre_id="T1110.003",
                    mitre_tactic="Credential Access",
                )
            )

    rows.sort(key=lambda r: r["@timestamp"])
    _write(rows, output_dir / "scenario_01_password_spray.csv")


# ---------------------------------------------------------------------------
# Scénario 2 — Kerberoasting (T1558.003)
# ---------------------------------------------------------------------------


def scenario_kerberoasting(output_dir: Path) -> None:
    """1 compte service avec 12 requêtes TGS (4769) en rafale sur 2 min."""
    rows = []
    user = USERS_KERB[0]
    attack_start = BASE_DATE.replace(hour=11, minute=30)

    # Logon initial
    rows.append(_row(attack_start, 4624, user, "3", "corp-wks08", "10.0.2.50"))

    # Rafale de requêtes Kerberos TGS
    for i in range(12):
        ts = attack_start + timedelta(seconds=10 + i * 10)
        rows.append(
            _row(
                ts,
                4769,
                user,
                "",
                "corp-dc01",
                "10.0.2.50",
                mitre_id="T1558.003",
                mitre_tactic="Credential Access",
                level=9,
            )
        )

    # Quelques processus suspects après l'extraction
    for proc, parent in [
        (r"C:\Tools\Rubeus.exe", r"C:\Windows\System32\cmd.exe"),
        (r"C:\Tools\mimikatz.exe", r"C:\Tools\Rubeus.exe"),
    ]:
        ts = attack_start + timedelta(minutes=3)
        rows.append(_row(ts, 4688, user, "", "corp-wks08", "10.0.2.50", proc, parent, level=12))

    rows.sort(key=lambda r: r["@timestamp"])
    _write(rows, output_dir / "scenario_02_kerberoasting.csv")


# ---------------------------------------------------------------------------
# Scénario 3 — Mouvement latéral (T1021)
# ---------------------------------------------------------------------------


def scenario_lateral_movement(output_dir: Path) -> None:
    """1 compte admin se connecte sur 8 hôtes distincts en 20 min."""
    rows = []
    user = USERS_LATERAL[0]
    attack_start = BASE_DATE.replace(hour=15, minute=0)
    hosts = [f"corp-srv{i:02d}" for i in range(1, 9)]

    # Logon initial sur la machine de l'attaquant
    rows.append(_row(attack_start, 4624, user, "3", "corp-wks09", "10.0.3.100"))

    # Connexions réseau rapides (type 3) sur 8 hôtes
    for i, host in enumerate(hosts):
        ts = attack_start + timedelta(minutes=i * 2 + 1)
        rows.append(
            _row(
                ts,
                4624,
                user,
                "3",
                host,
                "10.0.3.100",
                mitre_id="T1021",
                mitre_tactic="Lateral Movement",
            )
        )
        # Création de processus sur chaque hôte
        rows.append(
            _row(
                ts + timedelta(seconds=30),
                4688,
                user,
                "",
                host,
                "10.0.3.100",
                r"C:\Windows\System32\cmd.exe",
                r"C:\Windows\System32\services.exe",
            )
        )

    rows.sort(key=lambda r: r["@timestamp"])
    _write(rows, output_dir / "scenario_03_lateral_movement.csv")


def main() -> int:
    parser = argparse.ArgumentParser(description="Génère les CSV de scénarios d'attaque")
    parser.add_argument("--output-dir", default="data/scenarios", help="Répertoire de sortie")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)

    print("Génération des scénarios :")
    scenario_password_spray(output_dir)
    scenario_kerberoasting(output_dir)
    scenario_lateral_movement(output_dir)
    print("OK — 3 scénarios générés.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
