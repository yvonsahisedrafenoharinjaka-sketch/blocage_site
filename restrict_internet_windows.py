#!/usr/bin/env python3
"""
Script de restriction Internet (Windows 10 / 11)
 - Bloque tout le trafic sortant
 - Autorise uniquement certains sites (whitelist)
 - À exécuter en tant qu'administrateur
"""

import subprocess
import socket
import time


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

def main():
    while True:
        apply_firewall_rules()
        print("🔄 Attente avant la prochaine mise à jour (6h)...")
        time.sleep(6 * 3600) 
if __name__ == "__main__":
    apply_firewall_rules()
    
    main()
