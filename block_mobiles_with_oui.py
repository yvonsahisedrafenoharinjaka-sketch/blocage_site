import urllib.request
import re
import subprocess
import os
import sys

# URL officielle IEEE OUI (MA-L)
OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"

# Fichier temporaire pour stocker la base
OUI_FILE = os.path.join(os.path.dirname(sys.argv[0]), "oui.txt")

def download_oui():
    """Télécharge la base OUI IEEE"""
    try:
        print("Téléchargement de la base OUI...")
        urllib.request.urlretrieve(OUI_URL, OUI_FILE)
        print("Base OUI téléchargée avec succès.")
    except Exception as e:
        print(f"Erreur téléchargement OUI : {e}")

def extract_mobile_prefixes():
    """Extrait les préfixes MAC des fabricants mobiles"""
    mobile_keywords = ["Apple", "Samsung", "Huawei", "Xiaomi", "Oppo", "Vivo",
                       "OnePlus", "Google", "Motorola", "Nokia", "BlackBerry", "Sony"]
    prefixes = []
    try:
        with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = re.match(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(base 16\)\s+(.+)", line)
                if match:
                    mac_prefix, vendor = match.groups()
                    if any(keyword.lower() in vendor.lower() for keyword in mobile_keywords):
                        # Convertir le format XX-XX-XX → XX:XX:XX
                        prefixes.append(mac_prefix.replace("-", ":").upper())
    except Exception as e:
        print(f"Erreur lecture OUI : {e}")
    return prefixes

def block_mobile_mac(prefixes):
    """Crée des règles pare-feu Windows pour bloquer les appareils mobiles"""
    for prefix in prefixes:
        rule_name = f"BlockMobile_{prefix.replace(':', '')}"
        # Commande netsh pour bloquer par adresse MAC sur le réseau partagé (Hotspot)
        cmd = f'netsh wlan add filter permission=block ssid=* networktype=infrastructure mac={prefix}'
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            # Ignorer les erreurs si le filtre existe déjà
            pass

def main():
    download_oui()
    prefixes = extract_mobile_prefixes()
    block_mobile_mac(prefixes)
    print("Blocage des appareils mobiles terminé.")

if __name__ == "__main__":
    main()
