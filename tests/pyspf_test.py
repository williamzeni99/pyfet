import ipaddress
import regex
from typing import List
import spf

def test():
    print(spf.check2( i='198.37.150.87',s="bounce-48_HTML-180510831-27157-7258834-43@bounce.em.blizzard.com", h="o12.t.mail.accounts.riotgames.com" ))


def find_all_public_ips(header:str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    # Regex per trovare un ip
    ipv4_6 = r'((?:[0-9]{1,3}(?:[.][0-9]{1,3}){3})|(?:(?:(?:[a-fA-F0-9]{0,4})(?:[:][a-fA-F0-9]{0,4}){0,7})[:](?:(?:[:][a-fA-F0-9]{0,4})|(?:[0-9]{1,3}(?:[.][0-9]{1,3}){3}))))'
    
    matches = regex.findall(ipv4_6, header)
    ips=[]
    print(matches)
    for match in matches:
        try:
            ip = ipaddress.ip_address(match)
            if ip.is_global:
                ips.append(ip)    
        except:
            pass
    
    return ips


header = '''from mta9.link.adidas.com (13.111.30.137) by
 DB5PEPF00014B88.mail.protection.outlook.com (10.167.8.196) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.8069.17 via Frontend Transport; Wed, 16 Oct 2024 11:19:03 +0000'''

header2= '''from DB5PEPF00014B88.eurprd02.prod.outlook.com
 (2603:10a6:10:130:cafe::4a) by DB8P191CA0020.outlook.office365.com
 (2603:10a6:10:130.30.10.23) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8069.18 via Frontend
 Transport; Wed, 16 Oct 2024 11:19:03 +0000
'''

print(find_all_public_ips(header2+header))