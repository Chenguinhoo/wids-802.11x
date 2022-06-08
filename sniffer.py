import scapy.all as scapy
import os
import classes as cl
import constants as const

lClients = []
LClientaddrs = []
lAps = []
lApssid = []
lFakes = []

lDeauth = []
lDisas = []
lDos = []
lCont = []

detail = -1

###############
#Funciones get#
###############

def get_attack(p):
    if p.haslayer(scapy.Dot11):
        layer = p.getlayer(scapy.Dot11)
        if layer.type == 0 and layer.subtype == 12:
            tipo = "DEAUTH"
            code = 0
            victim = layer.addr1
            ap = layer.addr2
            timestamp = int(p.time)
            return cl.Attack(tipo, code, ap, victim, timestamp)
        elif layer.type == 0 and layer.subtype == 10:
            tipo = "DISASOC"
            code = 1
            victim = layer.addr1
            ap = layer.addr2
            timestamp = int(p.time)
            return cl.Attack(tipo, code, ap, victim, timestamp)

def get_attack2(tipo, code, ap, victim, timestamp):
    return cl.Attack(tipo, code, ap, victim, timestamp)

def get_ap(p):
    if p.haslayer(scapy.Dot11Beacon):
        bssid = p[scapy.Dot11].addr2
        ssid = p[scapy.Dot11Elt].info.decode()
        stats = p[scapy.Dot11Beacon].network_stats()
        channel = stats.get('channel')
        crypto = list(stats.get('crypto'))

        return cl.AP(ssid, bssid, channel, crypto)

def get_client(p):
    if p.haslayer(scapy.Dot11):
        layD11 = p.getlayer(scapy.Dot11)
        if layD11.type == 0 and layD11.subtype == 5:
            addr = layD11.addr1
            
            ssid = layD11.info.decode()
            bssid = layD11.addr3

            return cl.Client(addr, cl.APCl(ssid = ssid, bssid = bssid))

##################
#Funciones útiles#
##################

def write_log(index, text):
    f = open(const.LOGS[index], 'a')
    f.write(str(text) + '\n')
    f.close()
    if index == 2:
        alert_attack(text)
    if detail == 2:
        if index == 0 or index == 1:
            alert_actor(text, index)

#############################
#Funciones de inicialización#
#############################

def present():
    print('\n -----------------------------------------')
    print('\n| WIDS                                    |')
    print('\n| Hecho por Diego Fidalgo                 |')
    print('\n| Trabajo Fin de Master en Ciberseguridad |')
    print('\n| Universidad de Alcalá de Henares        |')
    print('\n -----------------------------------------')

def get_config():
    global detail
    detail = const.config['detail_level']

    ssid_p = const.config['ssid']
    ssid_n = const.config['ssid_n']
    if ssid_p != '':
        if ssid_n == '':
            ssid_n = 1
        config = cl.Config(ssid_p, ssid_n)
    return config

def check_files(path, files):
    if not os.path.exists(path):
        os.mkdir(path)
    for f in files:
        if not os.path.exists(f):
            open(f, 'x')

def check_sudo():
    if not 'SUDO_UID' in os.environ.keys():
        print("Intenta ejecutar con sudo...")
        exit()

def okay_lets_go(path, files):
    check_sudo()
    check_files(path, files)
    present()

##############################
#Funciones de análisis de red#
##############################

def sniffile(file):
    for i in range(0, len(const.ATAQUES)):
        lCont.append(0)
    reader = scapy.PcapReader(file)
    packets = reader.read_all()
    while 1:
        k = len(packets)
        packets = reader.read_all()
        analyze_packets(packets, k, len(packets))
        reader = scapy.PcapReader(file)
        print('.')

def analyze_packets(pList, start, end):
    for i in range(start, end):
        p = pList[i]
        check_actors(p)
        wids(p)

def wids(p):
    attack = get_attack(p)
    if attack:
        log_attack(attack)

def log_attack(attack):
    write_log(2, attack)
    if attack.code == 0:
        lDeauth.append(attack)
        check_more(attack)
    if attack.code == 1:
        lDisas.append(attack)
        check_more(attack)

def alert_attack(attack):
    if attack.code == 0:
        if detail != 0:
            print("Trama deauth recibida (from: %s, to: %s)..." % (attack.ap, attack.victim))
    if attack.code == 1:
        if detail != 0:
            print("Trama disasoc recibida (from: %s, to: %s)..." % (attack.ap, attack.victim))
    if attack.code == 2:
        if detail != 2: 
            print("Muchas tramas deauth/disasoc recibidas (from: %s, to: %s): posible ataque DoS" % (attack.ap, attack.victim))
    if attack.code == 3:
        if detail != 0:
            print("Punto de acceso falso detectado (SSID: %s, BSSID: %s)..." % (attack.ap, attack.victim))
    if attack.code == 4:
        if detail != 2:
            print("Tramas deauth recibidas (from: %s, to: %s): posible ataque al 4-way-handshake" % (attack.ap, attack.victim))

def alert_actor(actor, id):
    if id == 0:
        print("Nuevo punto de acceso descubierto (SSID: %s, BSSID: %s, Ch: %s, Crypto: %s)..." % (actor.ssid, actor.bssid, actor.channel, actor.crypto[0]))
    elif id == 1:
        print("Nueva conexión del cliente %s con el punto de acceso %s (%s)" % (actor.addr, actor.ap.ssid, actor.ap.bssid))

def check_more(attack):
    if attack.code == 0 and attack.victim == const.BROADCAST:
        if attack.timestamp - lDeauth[len(lDeauth) - 1].timestamp > 30:
            lCont[0] = 0
            lCont[2] = 0
        else:
            lCont[0] += 1
            lCont[2] += 1
            if lCont[2] == const.HSKNUM:
                hsk_attack = get_attack2("4WAYHANDSHAKE", 4, attack.ap, attack.victim, attack.timestamp)
                write_log(2, hsk_attack)
                lCont[2] = 0
            if lCont[0] == const.DOSNUM:
                dos_attack = get_attack2("DOS", 2, attack.ap, attack.victim, attack.timestamp)
                write_log(2, dos_attack)
                lDos.append(dos_attack)
                lCont[0] = 0
    if attack.code == 1:
        if attack.timestamp - lDisas[len(lDisas) - 1].timestamp > 30:
            lCont[1] = 0
        else:
            lCont[1] += 1
            if lCont[1] == 15:
                dos_attack = get_attack2("DOS", 2, attack.ap, attack.victim, attack.timestamp)
                write_log(2, dos_attack)
                lDos.append(dos_attack)
                lCont[1] = 0

def check_fake_ap(ap):
    ap2 = cl.APCl(ap.ssid, ap.bssid)
    if ap2 not in lFakes:
        if config is None:
            write_log(2, get_attack2("FAKE_AP", 3, ap.ssid, ap2.bssid, "-"))
            lFakes.append(ap2)
        elif config.ssid != '':
            naps_p = int(config.n)
            
            lCont[3] += 1
            if lCont[3] > naps_p:
                write_log(2, get_attack2("FAKE_AP", 3, ap2.ssid, ap2.bssid, "-"))
                lFakes.append(ap2)

def check_actors(p):
    ap = get_ap(p)
    if ap:
        if ap not in lAps:
            lAps.append(ap)
            write_log(0, ap)
            if config is not None:
                if ap.ssid == config.ssid and int(config.n) == 0:
                    write_log(2, get_attack2("FAKE_AP", 3, ap.ssid, ap.bssid, "-"))
                elif ap.ssid == config.ssid:
                    lCont[3] += 1
                    if lCont[3] > int(config.n):
                        write_log(2, get_attack2("FAKE_AP", 3, ap.ssid, ap.bssid, "-"))
            else:    
                if ap.ssid in lApssid:
                    check_fake_ap(ap)
                else:
                    lApssid.append(ap.ssid)
                    write_log(3, ap.ssid)
    
    client = get_client(p)
    if client:
        if client not in lClients:
            lClients.append(client)
            write_log(1, client)

######################################################################

if __name__ == '__main__':
    okay_lets_go(const.config['log_path'], const.LOGS)
    if os.path.exists(const.CONFILE):
        config = get_config()
        if detail == 0:
            detail_string = 'BAJO'
        elif detail == 1:
            detail_string = 'MEDIO'
        elif detail == 2:
            detail_string = 'ALTO'
        print('\nNivel de alertas: %s' % (detail_string))
        if config:
            print(config)
    else:
        print('ERROR: FICHERO DE CONFIGURACIÓN (%s) NO ENCONTRADO' % (const.CONFILE))
        exit
    print('\n -----------------------------------------')
    print('\n| Arranca el WIDS...                      |')
    print('\n -----------------------------------------')
    sniffile(const.PCAPS[const.config['n_fichero']])