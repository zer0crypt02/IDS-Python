import os
import time
from scapy.all import sniff, ARP, get_if_hwaddr
from collections import defaultdict
from colorama import Fore, Style, init # pip install
from tabulate import tabulate # pip install

# Colorama'yı başlatıyoruz
init(autoreset=True)

# ARP tablosunu kaydetmek için bir sözlük
arp_cache = {}

# Ağda tespit edilen saldırganları kaydedeceğimiz sözlük
attacker_ips = defaultdict(int)

# Ağ arayüzü (Wi-Fi bağlantısı için en0)
interface = "en0"  # Ağ arayüzünü doğru şekilde ayarlayın (Wi-Fi için en0)

# Kendi MAC adresinizi almak
try:
    my_mac = get_if_hwaddr(interface)
    print(Fore.GREEN + f"MAC adresiniz: {my_mac}")
except Exception as e:
    print(Fore.RED + f"MAC adresini almakta hata oluştu: {e}")

# Terminali temizlemek için platforma bağlı komut
def clear_terminal():
    if os.name == 'posix':  # macOS veya Linux için
        os.system('clear')
    elif os.name == 'nt':  # Windows için
        os.system('cls')

# ARP Spoofing saldırısını tespit eden fonksiyon
def detect_arp_spoofing(packet):
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        ip_src = arp_layer.psrc
        mac_src = arp_layer.hwsrc

        # Eğer bu IP adresi daha önce kaydedildiyse, MAC adresini kontrol et
        if ip_src in arp_cache:
            if arp_cache[ip_src] != mac_src:
                attacker_ips[ip_src] += 1
                print(Fore.RED + f"\nSaldırı tespit edildi! {Fore.YELLOW}IP: {ip_src} | MAC: {mac_src} yanlış! (Gerçek MAC: {arp_cache[ip_src]})")
                time.sleep(2)  # Yeni saldırı tespiti sonrası 2 saniye bekle
                print(Fore.CYAN + "-" * 50)
        
        # IP-MAC eşleşmesini güncelle
        arp_cache[ip_src] = mac_src

# Terminali temizle
clear_terminal()

# Başlangıç mesajı
print(Fore.CYAN + Style.BRIGHT + "Ağ trafiği izleniyor...")
print(Fore.CYAN + "-" * 50)

# Ağ trafiğini izlemeye başla
try:
    sniff(prn=detect_arp_spoofing, filter="arp", store=0, iface=interface, count=0)
except Exception as e:
    print(Fore.RED + f"Sniffing hatası: {e}")

# Saldırganları listele
def display_attackers():
    if attacker_ips:
        print(Fore.CYAN + "\nSaldırı Yapan Cihazlar:")
        attackers_table = []
        for ip, count in attacker_ips.items():
            attackers_table.append([ip, count])
        
        # Tabloyu güzel bir formatta yazdırıyoruz
        print(tabulate(attackers_table, headers=["IP Adresi", "Saldırı Sayısı"], tablefmt="fancy_grid", numalign="center"))
    else:
        print(Fore.GREEN + "Şu an tespit edilen saldırgan yok.")

# 2 saniye bekleme
time.sleep(2)

# Saldırı tespitlerini estetik bir şekilde yazdır
display_attackers()
