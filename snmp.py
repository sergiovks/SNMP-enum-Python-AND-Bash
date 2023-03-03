import argparse
from pysnmp.hlapi import *

# Define SNMP OIDs to retrieve system information
sysDescr = '1.3.6.1.2.1.1.1.0'
sysObjectID = '1.3.6.1.2.1.1.2.0'
sysUpTime = '1.3.6.1.2.1.1.3.0'
sysContact = '1.3.6.1.2.1.1.4.0'
sysName = '1.3.6.1.2.1.1.5.0'
sysLocation = '1.3.6.1.2.1.1.6.0'

def banner():
    print("""
    *********************************************
        SNMP Enumeration Tool
        Author: sergiovks
    *********************************************
    """)

def snmp_get(ip_address, community, oid):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community),
               UdpTransportTarget((ip_address, 161)),
               ContextData(),
               ObjectType(ObjectIdentity(oid)))
    )
    if errorIndication:
        print(errorIndication)
        return None
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        return None
    else:
        return varBinds[0][1]

def main():
    banner
    parser = argparse.ArgumentParser(description='Retrieve system information using SNMP')
    parser.add_argument('-t', '--target', type=str, help='Target IP address', required=True)
    parser.add_argument('-w', '--wordlist', type=str, help='Wordlist for community string', default=None)
    args = parser.parse_args()

    if args.wordlist:
        with open(args.wordlist) as f:
            for line in f:
                community_string = line.strip()
                sys_descr = snmp_get(args.target, community_string, sysDescr)
                if sys_descr:
                    print(f'System Description ({args.target}): {sys_descr}')
                    break
    else:
        community_string = 'public'
        sys_descr = snmp_get(args.target, community_string, sysDescr)
        if sys_descr:
            print(f'System Description ({args.target}): {sys_descr}')
        else:
            print(f'Could not retrieve system information from {args.target} using SNMP')

if __name__ == '__main__':
    main()

