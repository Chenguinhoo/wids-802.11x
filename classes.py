class Attack():
    def __init__(self, tipo, code, ap, victim, timestamp):
        self.tipo = tipo
        self.code = code
        self.ap = ap
        self.victim = victim
        self.timestamp = timestamp

    def __repr__(self):
        return("Attack(%s (%s)) from %s -> %s @ %s" % (self.tipo, self.code, self.ap, self.victim, self.timestamp))

    def __eq__(self, other):
        return self.tipo == other.tipo and self.ap == other.ap and self.victim == other.victim and self.timestamp == other.timestamp

class AP():
    def __init__(self, ssid, bssid, channel, crypto):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.crypto = crypto

    def __repr__(self):
        return("Access Point %s (%s) => Channel %s, Crypto %s" % (self.ssid, self.bssid, self.channel, self.crypto))
    
    def __eq__(self, other):
        return self.ssid == other.ssid and self.bssid == other.bssid

class APCl():
    def __init__(self, ssid, bssid):
        self.ssid = ssid
        self.bssid = bssid
    
    def __repr__(self):
        return("Access Point %s (%s)" % (self.ssid, self.bssid))
    
    def __eq__(self, other):
        return self.ssid == other.ssid and self.bssid == other.bssid

class Client():
    def __init__(self, addr, ap):
        self.addr = addr
        self.ap = ap
    
    def __repr__(self):
        return("Client %s @ %s" % (self.addr, self.ap))
    
    def __eq__(self, other):
        return self.addr == other.addr and self.ap == other.ap

class Config():
    def __init__(self, ssid, n):
        self.ssid = ssid
        self.n = n
    
    def __repr__(self):
        return("Punto de acceso configurado ( %s | %s )" % (self.ssid, self.n))