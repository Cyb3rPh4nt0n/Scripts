#Wi-Fi Scan by Cyb3rph4nt0n

#Módulos
import pywifi
from pywifi import const
import time

#Colores
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
PURPLE = "\033[35m"
END = "\033[39m"

#Escaner de redes
def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    print(f"\n{YELLOW}[*]{END} {BLUE}Usando interfaz:{END} {RED}{iface.name()}{END}")
    iface.scan()
    time.sleep(3)
    results = iface.scan_results()

    unique_networks = {}

    for network in results:
        ssid = network.ssid if network.ssid else "<Oculta>"

        if ssid not in unique_networks:

            auth = network.akm
            if const.AKM_TYPE_WPA in auth:
                security = "WPA"
            elif const.AKM_TYPE_WPAPSK in auth:
                security = "WPA (PSK)"
            elif const.AKM_TYPE_WPA2 in auth:
                security = "WPA2"
            elif const.AKM_TYPE_WPA2PSK in auth:
                security = "WPA2 (PSK)"
            elif const.AKM_TYPE_NONE in auth:
                security = "Abierta"
            else:
                security = "Otro/Desconocido"

            unique_networks[ssid] = {
                "bssid": network.bssid,
                "security": security
            }

    print(f"\n{YELLOW}[*]{END} {BLUE}Se encontraron {END}{GREEN}{len(unique_networks)}{END} {BLUE}redes únicas:{END}\n")
    print(f"{'SSID':<30} {BLACK}|{END} {'BSSID (MAC)':<20} {BLACK}|{END} {'Seguridad':<15}")
    print(f"{BLACK}-{END}" * 70)

    for ssid, info in unique_networks.items():
        print(f"{ssid:<30} {BLACK}|{END} {info['bssid']:<20} {BLACK}|{END} {info['security']:<15}")
        
if __name__ == '__main__':
    scan_wifi()
    print("\n")