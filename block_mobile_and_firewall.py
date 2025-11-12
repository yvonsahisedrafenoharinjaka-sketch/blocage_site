#!/usr/bin/env python3
"""
Script combiné :
 - Bloque les appareils mobiles sur le partage de connexion
 - Bloque tout le trafic sortant sauf une whitelist
 - Compatible Windows 10 / 11
"""

import urllib.request
import re
import subprocess
import socket
import time
import os
import sys

# --------------------
# Configuration OUI
# --------------------
OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"
OUI_FILE = os.path.join(os.path.dirname(sys.argv[0]), "oui.txt")

MOBILE_KEYWORDS = [
    "Apple", "Samsung", "Huawei", "Xiaomi", "Oppo", "Vivo",
    "OnePlus", "Google", "Motorola", "Nokia", "BlackBerry", "Sony"
]

# --------------------
# Whitelist sites
# --------------------
WHITELIST = [
    "dcp.assttl.uk",
    "mail.google.com",
    "accounts.google.com",
    "ssl.gstatic.com",
    "www.gstatic.com",
    "lh3.googleusercontent.com",
    "docs.google.com",
    "drive.google.com",
    "spreadsheets.google.com",
    "apis.google.com",
    "fonts.gstatic.com",
    "docs.googleusercontent.com"
]

# --------------------
# Fonctions utilitaires
# --------------------
def download_oui():
    try:
        print("Téléchargement de la base OUI...")
        urllib.request.urlretrieve(OUI_URL, OUI_FILE)
        print("Base OUI téléchargée.")
    except Exception as e:
        print(f"Erreur téléchargement OUI : {e}")

def extract_mobile_prefixes():
    prefixes = []
    try:
        with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(base 16\)\s+(.+)", line)
                if match:
                    mac_prefix, vendor = match.groups()
                    if any(keyword.lower() in vendor.lower() for keyword in MOBILE_KEYWORDS):
                        prefixes.append(mac_prefix.replace("-", ":").upper())
    except Exception as e:
        print(f"Erreur lecture OUI : {e}")
    return prefixes

def block_mobile_mac(prefixes):
    for prefix in prefixes:
        cmd = f'netsh wlan add filter permission=block ssid=* networktype=infrastructure mac={prefix}'
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass  # ignore si déjà présent

def ps(cmd):
    subprocess.run(["powershell", "-Command", cmd], check=False)

def resolve_ips(domain):
    try:
        return {r[4][0] for r in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except Exception as e:
        print(f"Erreur de résolution pour {domain}: {e}")
        return set()

def apply_firewall_rules():
    print("→ Application des règles du pare-feu...")
    ps("Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block")
    ps("netsh advfirewall firewall add rule name='Allow DNS Out' dir=out action=allow protocol=UDP remoteport=53")
    ps("netsh advfirewall firewall add rule name='Allow DNS TCP' dir=out action=allow protocol=TCP remoteport=53")

    allowed_ips = set()
    for site in WHITELIST:
        ips = resolve_ips(site)
        print(f"{site} → {ips}")
        allowed_ips |= ips

    for ip in allowed_ips:
        rule_name = f"Allow {ip}"
        cmd = f"netsh advfirewall firewall add rule name='{rule_name}' dir=out action=allow protocol=TCP remoteip={ip} remoteport=80,443"
        ps(cmd)

    print("✅ Règles appliquées. Seuls les sites whitelistés sont accessibles.")

# --------------------
# Main
# --------------------
def main_loop():
    while True:
        apply_firewall_rules()
        print("🔄 Attente avant la prochaine mise à jour (6h)...")
        time.sleep(6 * 3600)

def main():
    download_oui()
    prefixes = extract_mobile_prefixes()
    block_mobile_mac(prefixes)
    print("Blocage des appareils mobiles terminé.")

    # Applique le firewall au démarrage et boucle
    apply_firewall_rules()
    main_loop()

if __name__ == "__main__":
    main()
