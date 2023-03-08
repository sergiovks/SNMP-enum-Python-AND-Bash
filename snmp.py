#!/usr/bin/python3

import argparse
from pysnmp.hlapi import *
import time

# Define SNMP OIDs to retrieve system information
oids = [
    '1.3.6.1.2.1.1.5.0',  #System Name
    '1.3.6.1.2.1.1.1.0',  #System Description
    '1.3.6.1.2.1.1.2.0',  #System OIDs (Obejct IDs)
    '1.3.6.1.2.1.1.3.0',  #System UpTime
    '1.3.6.1.2.1.1.4.0',  #System Contact
    '1.3.6.1.2.1.1.6.0',  #System Location
    '1.3.6.1.2.1.25.4.2.1.2',  #Running Windows Processes/Programs
    '1.3.6.1.2.1.25.4.2.1.4',  #Processes Paths
    '1.3.6.1.2.1.25.2.3.1.4',  #Storage Units
    '1.3.6.1.2.1.25.6.3.1.2',  #Installed Software
    '1.3.6.1.4.1.77.1.2.25',  #User Accounts
    '1.3.6.1.2.1.6.13.1.3'   #Open TCP ports
]

def banner():
    print("""
    *********************************************
        SNMP Enumeration Tool
        Author: sergiovks
    *********************************************
    """)

def snmp_get(target, community, oid, retries, timeout):
    for i in range(retries):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community),
                   UdpTransportTarget((target, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)),
                   timeout=timeout)
        )
        if errorIndication:
            if 'No SNMP response received before timeout' in errorIndication:
                return None
            print(f'Error: {errorIndication} (community: {community}, retry: {i + 1}/{retries})')
            if i == retries - 1:
                return None
            time.sleep(1)
        elif errorStatus:
            print(f'Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"} (community: {community}, retry: {i + 1}/{retries})')
            if i == retries - 1:
                return None
            time.sleep(1)
        else:
            print(f'{oid} ({target}, community: {community}): {varBinds[0][1]}')
            return varBinds[0][1]

    return None

def main():
    banner()
    parser = argparse.ArgumentParser(description='Retrieve system information using SNMP')
    parser.add_argument('-t', '--target', type=str, help='Target IP address, NEEDED ARGUMENT')
    parser.add_argument('-w', '--wordlist', type=str, help='Wordlist for community string', default=None)
    parser.add_argument('-I', '--display-info', action='store_true', help='Display info/functionality panel')
    parser.add_argument('-r', '--retries', type=int, default=1, help='Number of tries, default=1 (Use 1 or more)')
    parser.add_argument('-to', '--timeout', type=int, default=5, help='Timeout in seconds, default=5')
    args = parser.parse_args()

    if args.display_info:
        print('System information can be retrieved using SNMP with this script.')
        print('Please provide the target IP address with -t or --target parameter.')
        print('If a community string is required, you can either provide it with -w or --wordlist parameter ')
        print('for a wordlist file or it will use the default "public" string.')
        print('Use -r or --retries if you want to try more times (default is 0)')
        print('Use -to or --timeout to specify the time (in seconds) that you want to wait for a response, default is 5')
        print('Use -I or --display-info to display this info about the script')
        print('\nThe script retrieves the following system information using predefined OIDs:\n')
        print('1.3.6.1.2.1.1.1.0,  System Description')
        print('1.3.6.1.2.1.1.2.0,  System OIDs (Obejct IDs)')
        print('1.3.6.1.2.1.1.3.0,  System UpTime')
        print('1.3.6.1.2.1.1.4.0,  System Contact')
        print('1.3.6.1.2.1.1.5.0,  System Name')
        print('1.3.6.1.2.1.1.6.0,  System Location')
        print('1.3.6.1.2.1.25.4.2.1.2,  Running Windows Processes/Programs')
        print('1.3.6.1.2.1.25.4.2.1.4,  Processes Paths')
        print('1.3.6.1.2.1.25.2.3.1.4,  Storage Units')
        print('1.3.6.1.2.1.25.6.3.1.2,  Installed Software')
        print('1.3.6.1.4.1.77.1.2.25,  User Accounts')
        print('1.3.6.1.2.1.6.13.1.3   Open TCP ports')
    else:
        # Retrieve system information
        target = args.target
        community = args.wordlist or 'public'
        retries = args.retries
        timeout = args.timeout
        snmp_get
    
    if not args.target:
        parser.print_help()
        return

    failed_communities = {}
    if args.wordlist:
        with open(args.wordlist) as f:
            for line in f:
                community_string = line.strip()
                for oid in oids:
                    if community_string in failed_communities:
                        break
                    value = snmp_get(args.target, community_string, oid, args.retries, args.timeout)
                    if value is None and oid == oids[-1]:
                        failed_communities[community_string] = True
                    elif value is not None:
                        failed_communities.pop(community_string, None)
    else:
        community_string = 'public'
        for oid in oids:
            if community_string in failed_communities:
                break
            value = snmp_get(args.target, community_string, oid, args.retries, args.timeout)
            if value is None and oid == oids[-1]:
                failed_communities[community_string] = True
            elif value is not None:
                failed_communities.pop(community_string, None)

if __name__ == '__main__':
    main()
