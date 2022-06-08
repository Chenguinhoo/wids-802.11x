'''
CODIGOS DE LOS ATAQUES
- 0 = Deauth
- 1 = Disasoc
- 2 = DoS
- 3 = Fake AP
- 4 = 4-way-handshake
'''

import yaml as yaml

CONFILE = 'wids_config.yaml'
BROADCAST = 'ff:ff:ff:ff:ff:ff'
PCAPS = ['fake_aps.pcap', 'deauth.pcap', 'disasoc.pcap']
LOGS = ['aps.wids', 'clients.wids', 'attacks.wids', 'ap_ssids.wids']
ATAQUES = ["DEAUTH", "DISAS", "4WAY", "FAP"]

with open(CONFILE, 'r') as f:
    config = yaml.load(f, Loader = yaml.FullLoader)

for i in range(len(PCAPS)):
    PCAPS[i] = config['pcap_path'] + PCAPS[i]

for i in range(len(LOGS)):
    LOGS[i] = config['log_path'] + LOGS[i]

DOSNUM = config['max_dos']
HSKNUM = config['max_ksk']