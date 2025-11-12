#!/usr/bin/env python3
"""
block_mobiles_autoelev.py

- Se ré-exécute avec élévation UAC si nécessaire.
- Scanne régulièrement `arp -a` pour trouver (IP, MAC).
- Compare l'OUI MAC avec une table mobile (heuristique).
- Ajoute une règle Windows Firewall pour bloquer l'IP distante.
- Garde un journal simple et évite doublons.

Usage:
  python block_mobiles_autoelev.py
  (ou packager en .exe — instructions après)

Remarques:
- Nécessite des droits administrateur pour modifier le pare-feu.
- La détection par OUI n'est pas infaillible (MAC randomisé, Apple fabrique aussi MacBooks).
"""
import sys
import os
import re
import subprocess
import time
import ctypes
from datetime import datetime

# ----------------- CONFIG -----------------
SCAN_INTERVAL = 8        # secondes entre scans
RULE_PREFIX = "AutoBlockMobile_"  # nom de préfixe pour règles créées
LOG_FILE = os.path.join(os.path.dirname(__file__), "block_mobiles.log")

# Petite table OUI d'exemples (majuscule, 3 octets)
MOBILE_OUIS = {
    "28:FF:3E": "Apple, Inc.",
    "A4:5E:60": "Apple, Inc.",
    "F0:99:B6": "Samsung Electronics",
    "CC:6E:A4": "Samsung Electronics",
    "C8:7B:23": "Huawei Technologies",
    "B0:5C:DA": "Huawei Technologies",
    "FC:0F:AF": "Xiaomi Communications",
    "04:CF:8C": "Xiaomi Communications",
    "3C:5A:B4": "Google, Inc.",
    "64:E7:4C": "OnePlus Technology",
    "54:4A:16": "OPPO Electronics",
    "A4:77:33": "vivo Mobile Communication",
    "E4:12:5F": "Motorola Mobility",
    "00:1A:79": "Sony Mobile",
    "F8:77:66": "Nokia Mobile"
}

# ----------------- UTIL -----------------
def log(msg):
    line = f"{datetime.now().isoformat()} {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate_if_needed():
    """Relance l'exécutable/commande avec élévation UAC si pas admin."""
    if is_admin():
        return
    # build command to re-run the same script with admin privileges
    params = " ".join([f'"{x}"' for x in sys.argv])
    python_exe = sys.executable
    # Use ShellExecuteEx with runas
    ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, None, 1)
    log("Relancement demandé avec élévation (UAC). Le processus actuel va quitter.")
    sys.exit(0)

def normalise_mac(mac):
    clean = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
    if len(clean) != 12:
        return None
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))

# ----------------- RÉCUPÉRER ARP -----------------
ARP_LINE_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f\:\-]{17})")

def get_arp_entries():
    """Retourne une liste de tuples (ip, mac) à partir de 'arp -a'."""
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        out = proc.stdout
    except Exception as e:
        log(f"Erreur arp -a : {e}")
        return []
    entries = []
    for line in out.splitlines():
        m = ARP_LINE_RE.search(line)
        if m:
            ip = m.group(1)
            mac_raw = m.group(2)
            mac = normalise_mac(mac_raw)
            if mac:
                entries.append((ip, mac))
    return entries

# ----------------- PARE-FEU -----------------
def make_rule_name(ip):
    return RULE_PREFIX + ip.replace('.', '_')

def rule_exists(ip):
    name = make_rule_name(ip)
    # netsh advfirewall firewall show rule name="..." will return non-zero if not exists
    try:
        res = subprocess.run(['netsh','advfirewall','firewall','show','rule',f'name={name}'],
                             capture_output=True, text=True)
        return "No rules match" not in res.stdout
    except Exception:
        return False

def add_block_rule(ip):
    name = make_rule_name(ip)
    # Block both inbound and outbound to be safe (ou adapte selon besoin)
    cmds = [
        ['netsh','advfirewall','firewall','add','rule','name='+name,'dir=out','action=block','remoteip='+ip],
        ['netsh','advfirewall','firewall','add','rule','name='+name+'_in','dir=in','action=block','remoteip='+ip]
    ]
    for c in cmds:
        try:
            subprocess.run(c, capture_output=True, text=True, timeout=6)
        except Exception as e:
            log(f"Erreur ajout règle {name} : {e}")
    log(f"[BLOQUÉ] Règle créée pour {ip}")

def remove_all_rules():
    """Supprime toutes les règles créées par ce script (utile pour nettoyage)."""
    # Liste les règles puis supprime celles qui commencent par le préfixe
    try:
        res = subprocess.run(['netsh','advfirewall','firewall','show','rule','name=all'],
                             capture_output=True, text=True, timeout=10)
        text = res.stdout
        # simple parse : chercher les blocs "Rule Name: <name>"
        names = re.findall(r'Rule Name:\s*(.+)', text)
        for n in names:
            if n.startswith(RULE_PREFIX):
                subprocess.run(['netsh','advfirewall','firewall','delete','rule','name='+n], capture_output=True, text=True)
                log(f"Supprimé règle {n}")
    except Exception as e:
        log(f"Erreur suppression règles : {e}")

# ----------------- DÉTECTION MOBILE -----------------
def is_mobile_by_oui(mac):
    oui = ":".join(mac.split(':')[:3])
    return oui in MOBILE_OUIS

# ----------------- MAIN MONITOR -----------------
def monitor_loop():
    seen = set()  # macs déjà traités (pour éviter dupliquer logs)
    try:
        log("Démarrage du moniteur (mode auto).")
        while True:
            entries = get_arp_entries()
            for ip, mac in entries:
                if mac in seen:
                    continue
                seen.add(mac)
                if is_mobile_by_oui(mac):
                    log(f"Détecté mobile probable {ip} / {mac} ({MOBILE_OUIS.get(':'.join(mac.split(':')[:3]))})")
                    if not rule_exists(ip):
                        add_block_rule(ip)
                    else:
                        log(f"Règle existante pour {ip}, rien à faire.")
                else:
                    log(f"Appareil autorisé (probable PC) {ip} / {mac}")
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        log("Arrêt demandé (KeyboardInterrupt).")
    except Exception as e:
        log(f"Erreur inattendue dans la boucle: {e}")

# ----------------- ENTRYPOINT -----------------
def main():
    # Support simple args: --cleanup pour supprimer règles créées
    if '--cleanup' in sys.argv:
        if not is_admin():
            elevate_if_needed()
        remove_all_rules()
        return
    # Elevate if not admin
    if not is_admin():
        elevate_if_needed()
    # start monitoring
    monitor_loop()

if __name__ == '__main__':
    main()
