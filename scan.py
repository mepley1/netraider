import ipaddress
import logging
import sqlite3
import scapy.all as scapy
import socket
import sys
import threading
import time
import json

# Timeout to use with scapy, for consistency
DEFAULT_TIMEOUT = 5
PORT_SCAN_TIMEOUT = 1

def send_arp_request(ip: str, results: list, lock, interface) -> None:
    ''' Send individual ARP request for <ip> and append any response to <results>.
    Called by below arp_scan_threaded() function. '''
    # If no interface selected, use default (whichever scapy.conf.iface returns)
    if not interface:
        interface = scapy.conf.iface.name

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    request_broadcast = broadcast / arp_request 

    # Send request + get response
    resp = scapy.srp(request_broadcast, timeout=DEFAULT_TIMEOUT, verbose=False, iface=interface)[0]

    with lock:
        for _, packet in resp:
            results.append({'ip': packet.psrc, 'mac': packet.hwsrc})

def arp_scan_threaded(ip_range, progress_callback=None, stop_event=None, interface=None) -> list:
    '''Active ARP scan. Send an ARP request for each address in <ip_range>, and return results.'''

    # Determine IP addrs to scan
    ip_network = ipaddress.IPv4Network(ip_range, strict=False)
    ip_addresses = [str(ip) for ip in ip_network.hosts()]
    num_ips = ip_network.num_addresses

    if progress_callback:
        progress_callback(0, num_ips, f'ARP scan: {ip_range} ...', 'indeterminate')

    # Prep for multithreading the scan
    results = []
    lock = threading.Lock()
    threads = []

    # Create and start threads for each addr
    for ip in ip_addresses:
        arp_thread = threading.Thread(target=send_arp_request, args=(ip, results, lock, interface))
        threads.append(arp_thread)
        arp_thread.start()

        #Update progress bar
        if progress_callback:
            progress_callback(len(results), num_ips, f'ARP scan: {ip_range} ...', 'indeterminate')

        # Check for stop event
        if stop_event and stop_event.is_set():
            logging.info('Stopping ARP scan (stop event set).')
            return

    # Join threads
    for thread in threads:
        thread.join()

    # Stop progress bar
    if progress_callback:
        progress_callback(0, 0, 'Finished ARP scan.', 'stop')

    return results

def arp_scan(ip_range, progress_callback=None) -> list:
    ''' Active ARP scan. Send an ARP request for each address in <ip_range>, and return results. '''
    
    # Update progress bar
    if progress_callback:
            progress_callback(1, 3, 'Create ARP request...', 'determinate')

    #Create ARP request
    arp_request = scapy.ARP() 
    arp_request.pdst = ip_range

    broadcast = scapy.Ether() 
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    # Update progress bar
    _num_ips = ipaddress.IPv4Network(ip_range, strict=False).num_addresses
    if progress_callback:
        progress_callback(0, _num_ips, f'ARP scan: {ip_range} ...', 'indeterminate')

    request_broadcast = broadcast / arp_request 
    clients = scapy.srp(request_broadcast, timeout = DEFAULT_TIMEOUT)[0]

    #Print IP + MAC of each client found
    for client in clients:
        logging.info(client[1].psrc + "      " + client[1].hwsrc) 


    #Stop progress bar
    if progress_callback:
        progress_callback(0, 0, 'Finished', 'stop')

    return [{'ip': client[1].psrc, 'mac': client[1].hwsrc} for client in clients]

def ndp_scan(ipv6_prefix, progress_callback=None) -> list:
    ''' Active NDP/NS scan. Send a neighbor solicitation for each addr in <ipv6_prefix>, and return results.
    Note: This will send a NS packet for *every* address in the given prefix. 
    Depending on size of prefix, this may take a very long time (i.e. millions of years). 
    Not recommended to scan an IPv6 subnet in this manner. '''
    results = []

    # Generate list of v6 addrs to scan.
    ipv6_network = ipaddress.IPv6Network(ipv6_prefix, strict=False)

    # For progress bar callback
    total_hosts = ipv6_network.num_addresses
    if progress_callback:
        progress_callback(0, total_hosts, 'Neighbor solicitation..', 'determinate')

    _progress = 0 #for progress callback

    # Loop through addrs in ipv6_network and send NS packet
    for ipv6_address in ipv6_network:
        # Create neighbor solicitation packet
        ns_packet = (
            scapy.Ether(dst = '33:33:ff:00:00:00') /
            scapy.IPv6(dst = str(ipv6_address)) /
            #IPv6(dst = 'ff02::1') /
            scapy.ICMPv6ND_NS(tgt = str(ipv6_address)) /
            scapy.ICMPv6NDOptSrcLLAddr(lladdr = scapy.get_if_hwaddr(scapy.conf.iface))
        )

        # Send out the packet and wait for response
        ans, unans = scapy.srp(ns_packet, timeout = DEFAULT_TIMEOUT, retry = 0, verbose = False, threaded = True)

        # Parse response
        for sent, received in ans:
            if scapy.ICMPv6ND_NA in received and received[scapy.ICMPv6ND_NA].tgt == str(ipv6_address):
                mac_address = received[scapy.Ether].src
                results.append({'ip': str(ipv6_address), 'mac': mac_address})
                logging.info(f'ip: {ipv6_address}, mac: {mac_address}')

        _progress += 1
        if progress_callback:
            progress_callback(_progress, total_hosts, 'Neighbor solicitation...', 'determinate')

    logging.info(results)
    return results



def ping_host(ip_addrs: list, progress_callback=None, interface=None, stop_event=None) -> dict:
    ''' Ping a list of ip addresses, return response times as a dict. '''
    results = {}
    _progress = 0
    total_hosts = len(ip_addrs)

    # If no interface given, use whichever one scapy.conf.iface.name returns.
    if not interface:
        interface = scapy.conf.iface.name
    logging.debug(f'Interface: {interface}')

    # Loop through addresses
    for idx, addr in enumerate(ip_addrs):

        # Check if stop event set, and stop if so.
        if stop_event:
            if stop_event.is_set():
                logging.warning('Stopping ping.. (stop event set)')
                break

        # Update progress bar
        if progress_callback:
            progress_callback(idx+1, total_hosts, f'Ping hosts...', 'determinate')

        # Skip if item has no IP in db
        if addr == 'None':
            logging.error(f'Encountered missing/invalid IP addr, skipping. Addr: {addr}')
            continue

        # Determine IP version, and send ICMP ping
        ip_version = ipaddress.ip_address(addr).version
        match ip_version:
            case 4:
                i = scapy.IP()
                i.dst = addr
                req = scapy.ICMP()
                pkt = (i / req)

                # Send 4 pings, and add response times to resp_times list
                resp_times = []
                for numi in range(4):

                    # Check if stop event set, and stop if so.
                    if stop_event:
                        if stop_event.is_set():
                            logging.warning('Stopping ping.. (stop event set)')
                            break

                    # Send ping and calculate response time
                    resp = scapy.sr1(pkt, timeout = DEFAULT_TIMEOUT, iface=interface, verbose=False)
                    if resp:
                        rt_time = resp[1].time - pkt[0].sent_time
                        resp_times.append(rt_time)
                    else:
                        logging.debug('No response')
                        continue

                logging.debug(f'response times: {str(resp_times)}')

                # Calculate average response time
                if resp_times:
                    avg_time = sum(resp_times) / len(resp_times)
                else:
                    avg_time = None
                rt_time = avg_time
                if rt_time:
                    logging.debug(f'Average response time: {avg_time*1000} ms')
                ## END TEST
            case 6:
                i = scapy.IPv6()
                i.dst = addr
                req = scapy.ICMPv6EchoRequest()
                pkt = (i / req)
                resp = scapy.sr1(pkt, timeout = DEFAULT_TIMEOUT, iface=interface)
                if resp:
                    rt_time = resp[1].time - pkt[0].sent_time #same as above, just not rounded

        # Record results
        results[addr] = rt_time * 1000 if rt_time else None

        # Increment progress counter
        _progress += 1

    # Update progress bar when done.
    if progress_callback:
        if len(results.keys()) < 3:
            progress_callback(_progress, total_hosts, f'Received response from: {results.keys()}', 'determinate')
        else:
            progress_callback(_progress, total_hosts, f'Received response from {len(results.keys())} hosts', 'determinate')

    logging.info('Finished.')
    for i, result in enumerate(results):
        logging.info(f'{result}: {results[result]} ms')

    return results

## SNIFFERS ##

def sniff_arp(stop_event, interface=None, lock=None) -> None:
    ''' Sniff for ARP packets, grab any MACs + IPs seen. '''

    def sniff_arp(stop_event, interface):
        # Sniff until stop_event is set.
        logging.info(f'Sniffing on interface: {interface}')
        try:
            capture = scapy.sniff(store=False,
                filter='arp',
                prn=process_pkt,
                stop_filter=lambda x: stop_event.is_set(),
                iface=interface
                )
        except OSError as e:
            logging.error(f'Probably invalid interface. The following exception occurred: \n{str(e)}')

    def process_pkt(pkt):
        ''' For ARP sniffer. '''
        logging.debug(f'Source IP: {pkt[1].psrc} / Source MAC: {pkt.src}')
        logging.debug(f'Dest IP: {pkt[1].pdst} / Dest MAC: {pkt.dst}')
        # Extract MAC + IP for each host
        if pkt.dst != 'ff:ff:ff:ff:ff:ff': #Don't save if dstmac is broadcast
            hosts = [
                {'ip': pkt[1].psrc, 'mac': pkt.src},
                {'ip': pkt[1].pdst, 'mac': pkt.dst},
                ]
        else:
            logging.debug('Broadcast MAC seen, ignoring device.')
            hosts = [
                {'ip': pkt[1].psrc, 'mac': pkt.src},
                ]

        # NOTE: Dont add device with MAC FF:FF:FF:FF:FF:FF to database.
        add_to_database_by_ip(hosts, lock)

        if stop_event:
            if stop_event.is_set():
                logging.info('ARP sniffing finished.')

    sniff_arp(stop_event, interface)


def sniff_ip(stop_event=None, interface=None, lock=None) -> None:
    ''' Sniff IP packets, and write seen IPs+MACs to database. '''

    def _sniff_ip(stop_event, interface):
        logging.info(f'Sniffing for IP on interface: {interface}')
        try:
            capture = scapy.sniff(store=False,
                filter='ip',
                prn=process_pkt_ip,
                stop_filter=lambda x: stop_event.is_set(),
                iface=interface
                )
        except OSError as e:
            logging.error(f'Probably invalid interface. The following exception occurred: \n{str(e)}')

    def process_pkt_ip(pkt):
        ''' Process sniffed packet, for IP sniffer. 
        Is passed packet by prn function of scapy.sniff '''

        logging.debug(f'Source IP: {pkt[1].src} / Source MAC: {pkt[0].src}')
        logging.debug(f'Dest IP: {pkt[1].dst} / Dest MAC {pkt[0].dst}')
        # Save source and dest devices to db, if both local.
        # Try to get IP of local interface? scapy.conf.iface.ip
        #if ipaddress.ip_address(pkt[1].src).is_private and ipaddress.ip_address(pkt[1].dst).is_private: #if both ips are local
        if 1==1: #testing, skipping above private check - check for is.private later instead (for each individual host).
            #logging.debug('Hosts are local.')
            #if pkt[0].dst != 'ff:ff:ff:ff:ff:ff':
            hosts = [
                {'ip': pkt[1].src, 'mac': pkt[0].src}, #source host
                {'ip': pkt[1].dst, 'mac': pkt[0].dst}, #dest host
            ]

            # check if ips are private
            #src_ip = ipaddress.ip_address(pkt[1].src)
            #dst_ip = ipaddress.ip_address(pkt[1].dst)

            # same as above, but as a comprehension?
            hosts_not_bcast = [host for host in hosts if host['mac'] != 'ff:ff:ff:ff:ff:ff' and ipaddress.IPv4Address(host['ip']).is_private]
            #hosts_not_bcast = [host for host in hosts if host['mac'] != 'ff:ff:ff:ff:ff:ff']
            hosts_remote = [host for host in hosts if ipaddress.IPv4Address(host['ip']).is_global and not ipaddress.IPv4Address(host['ip']).is_multicast]
            if hosts_remote:
                logging.info(f'Remote hosts seen: {hosts_remote}')

            add_to_database_by_ip(hosts_not_bcast, lock)

            #Check if stop_event has been set, and stop if so.
            if stop_event:
                if stop_event.is_set():
                    logging.info('IP sniffing finished.')
        else:
            logging.info('Remote host, not saving.')
            # NOTE: To-do: Save any remote hosts contacted, to another table 'remote_hosts' just the IP - MAC would be router's MAC.

    _sniff_ip(stop_event, interface)

def sniff_ipv6(stop_event=None, interface=None):
    ''' Sniff for IPv6 IP packets. Write seen IPs+MACs to db. '''

    def _sniff_ipv6(stop_event, interface):
        logging.info(f'Sniffing IPv6 on interface: {interface}')
        try:
            capture = scapy.sniff(store=False, filter='ip6', prn=process_pkt_ip, stop_filter=lambda x: stop_event.is_set(), iface=interface)
        except OSError as e:
            logging.error(f'Probably invalid interface. The following exception occurred: \n{str(e)}')

    def process_pkt_ip(pkt):
        ''' Process sniffed packet, for IPv6 sniffer. 
        Is passed packet by prn function of scapy.sniff '''

        logging.info(f'Source IP: {pkt[1].src} / Source MAC: {pkt[0].src}')
        logging.info(f'Dest IP: {pkt[1].dst} / Dest MAC {pkt[0].dst}')
        # Save source and dest devices to db, if both local.

        hosts = [
            {'ip': pkt[1].src, 'mac': pkt[0].src}, #source host
            {'ip': pkt[1].dst, 'mac': pkt[0].dst}, #dest host
        ]

        # same as above, but as a comprehension?
        #hosts_not_bcast = [host for host in hosts if host['mac'] != 'ff:ff:ff:ff:ff:ff' and ipaddress.IPv6Address(host['ip']).is_private]
        hosts_private = [host for host in hosts if ipaddress.IPv6Address(host['ip']).is_private]

        # Also include host if it's in any of local prefixes, since v6 (mostly) won't be NAT'ed
        for host in hosts:
            for pfix in get_v6_prefixes():
                if ipaddress.IPv6Address(host['ip']) in pfix:
                    hosts_private.append(host)

        #hosts_remote = [host for host in hosts if ipaddress.IPv6Address(host['ip']).is_global and not ipaddress.IPv6Address(host['ip']).is_multicast]
        
        #if hosts_remote:
        #    logging.info(f'Remote hosts seen: {hosts_remote}')

        #add_to_database_by_ipv6(hosts_private)
        # Testing new JSON version
        logging.debug(f'hosts_private: {hosts_private}')
        add_to_database_by_ipv6_json(hosts_private)

        if stop_event:
            if stop_event.is_set():
                logging.info('IPv6 sniffing finished.')

    _sniff_ipv6(stop_event, interface)
## End sniffers ##

def tcp_syn_scan(target_ip=None, progress_callback=None, stop_event=None):
    ''' Perform simple TCP SYN scan on target ip. '''
    target_ip = target_ip
    addr_version = ipaddress.ip_address(target_ip).version
    active_ports = []
    ports = [22, 23, 25, 69, 80, 443]
    ports_dict = {
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        67: 'dhcp',
        68: 'dhcp',
        69: 'tftp',
        80: 'http',
        139: 'smb netbios',
        143: 'imap',
        389: 'ldap',
        443: 'https',
        445: 'smb',
        636: 'ldaps',
        3142: 'proxy', #common port for squid/apt-cacher-ng etc
        3389: 'rdp',
        5380: 'technitium web interface http',
        53443: 'technitium web interface https',
        8291: 'winbox',
        8728: 'routeros api',
        8729: 'routeros api ssl',

    }
    num_ports = len(ports_dict)

    logging.debug(f'TCP scan target IP: {target_ip}')
    # Perform SYN scan
    for i, port in enumerate(ports_dict.keys()):
        # if stop event set, stop and return.
        if stop_event and stop_event.is_set():
            if progress_callback:
                progress_callback(i+1, num_ports, 'TCP SYN scan STOPPED.', 'determinate')
            return
        # progress callback
        if progress_callback:
            progress_callback(i+1, num_ports, 'TCP SYN scan...', 'determinate')

        # Create + send TCP packets
        match addr_version:
            case 4:
                packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S")
            case 6:
                packet = scapy.IPv6(dst=target_ip) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=PORT_SCAN_TIMEOUT, verbose=0)
        if response:
            if response[scapy.TCP].flags == "SA":
                logging.debug(f"Port {port} open.")
                active_ports.append(port)
            elif response[scapy.TCP].flags == "RA":
                logging.debug(f"Port {port} closed.")

    return(active_ports)





## DATABASE FUNCTIONS ##

def write_ports_by_id(dev_id: int, ports: list, lock=None) -> None:
    ''' Write port scan results to database. '''
    # Convert list to JSON string
    try:
        ports_json = json.dumps(ports)
    except json.JSONDecodeError as e:
        #NOTE: Is this left over from previous code? Shouldn't be encountering JSONDecodeError when passed a list
        logging.error(f'Error - bad JSON. {str(e)}')

    # Write it to db
    with lock:
        with sqlite3.connect('network_devices.db') as conn:
            c = conn.cursor()
            sql_query = '''
                UPDATE devices
                SET ports = ?
                WHERE id = ?;
            '''
            data_tuple = (ports_json, dev_id)
            c.execute(sql_query, data_tuple)
            conn.commit()
        conn.close()

#UNUSED YET
def get_ipv6_by_id(dev_id) -> list:
    ''' Retrieve a device's IPv6 addrs from database and return as list. '''
    with sqlite3.connect('network_devices.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = 'SELECT ipv6_address FROM devices WHERE id = ?;'
        data_tuple = (dev_id,)
        c.execute(sql_query, data_tuple)
        results = c.fetchone()[0]
    conn.close()
    results = json.loads(results)
    return results

def initialize_db() -> None:
    ''' Create database. '''
    with sqlite3.connect('network_devices.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Create 'devices' table if it doesn't already exist
        c.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT,
                ip_address INTEGER,
                mac_address TEXT,
                ipv6_address TEXT,
                ping_time NUMERIC,
                ports TEXT
            )
        ;''')
        conn.commit()
    conn.close()

def add_to_database_by_ip(hosts, lock) -> bool:
    ''' Add given hosts to db- MAC+IP only. For use with IP/ARP sniffer. 
    Returns true if no exceptions.'''
    with lock:
        with sqlite3.connect('network_devices.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            for host in hosts:
                # Check if MAC already exists in db with same IP
                # NOTE: To-do: Select id AND ip. Check for MAC first, then check if it has the same IP. If not same IP, then either it's multihomed or IP changed.
                #sql_query = '''SELECT id FROM devices WHERE mac_address LIKE ? AND ip_address = ?'''
                sql_query = '''SELECT id, ip_address FROM devices WHERE mac_address LIKE ?;''' #NEW 8-14
                #data_tuple = (host['mac'], int(ipaddress.ip_address(host['ip'])))
                data_tuple = (host['mac'],) #NEW 8-14
                c.execute(sql_query, data_tuple)

                try:
                    #result = c.fetchone()[0]
                    result = c.fetchone() #NEW VERSION 8-14
                    logging.info('Device already in database.')
                    logging.debug(f'Device data in db: id {result["id"]}, ip {result["ip_address"]}')
                    dev_in_db = True
                except Exception as e:
                    result = 0
                    logging.debug(str(e))
                    logging.info('Device not in database.')
                    dev_in_db = False

                if not result: #If device NOT in database, add it
                    logging.info(f'Adding device to database with MAC {host["mac"]}...')
                    sql_query = '''
                        INSERT INTO devices (mac_address, ip_address)
                        VALUES (?, ?)
                        '''
                    data_tuple = (host['mac'], int(ipaddress.ip_address(host['ip']))) #NEW TUPLE 8-14 (previously already had made same tuple and re-used)
                    c.execute(sql_query, data_tuple)
                    logging.info('Success.')
                # Testing:
                elif 1==1:
                    print(f'DEBUG: ip in database: {ipaddress.IPv4Address(result["ip_address"])} / sniffed ip: {host["ip"]}')
                
                # If sniffed ip and stored IP don't match, update record if sniffed ip isnt 0.0.0.0
                if result:
                    if result['ip_address'] == int(ipaddress.ip_address(host['ip'])): #NEW 8/14: Check if stored IP and sniffed IP match. If not, update it.
                        logging.debug('Sniffed IP matches stored IP. Nothing to update.')
                    elif result['ip_address'] != int(ipaddress.ip_address(host['ip'])): #NEW ALSO
                        logging.debug(f"Sniffed IP does NOT match stored ip. \nStored: {result['ip_address']} - Sniffed: {int(ipaddress.ip_address(host['ip']))}")
                        logging.debug(f'Updating device {result["id"]}...')
                        # Now update the record as long as sniffed ip not 0.0.0.0
                        # NOTE: Add check to catch sniffed IP == 0. block below only checks for STORED ip = 0
                        if result['ip_address'] == 0:
                            logging.debug('Stored IP addr is 0. Updating.')
                            sql_query = '''
                                UPDATE devices
                                SET ip_address = ?
                                WHERE id = ?;
                            '''
                            data_tuple = (int(ipaddress.IPv4Address(host['ip'])), result['id'])
                            c.execute(sql_query, data_tuple)
                        else:
                            logging.debug('Sniffed IP is 0, where stored IP is good. Skipping update.')

            conn.commit()
        conn.close()

    return True

def add_to_database_by_ipv6(hosts) -> bool:
    ''' Add given hosts to db- MAC+IPv6 addr only. For use with IP sniffer. 
    Returns true if no exceptions.'''
    with sqlite3.connect('network_devices.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        for host in hosts:
            # Check if MAC already exists in db with same IP
            sql_query = '''SELECT id FROM devices WHERE mac_address LIKE ? AND ipv6_address LIKE ?'''
            data_tuple = (host['mac'], host['ip'])
            c.execute(sql_query, data_tuple)

            try:
                result = c.fetchone()[0]
                logging.info('Device already in database.')
            except Exception as e:
                result = 0
                logging.debug(str(e))
                logging.info('Device not in database.')

            if not result: #If device NOT in database, add it
                logging.info(f'Adding device to database with MAC {host["mac"]}...')
                sql_query = '''
                    INSERT INTO devices (mac_address, ipv6_address, ip_address)
                    VALUES (?, ?, 0)
                    '''
                c.execute(sql_query, data_tuple)
                logging.info('Success.')

        conn.commit()
    conn.close()

    return True

def add_to_database_by_ipv6_json(hosts: list) -> None:
    ''' Write IPv6 addrs to db as JSON string. '''

    for host in hosts:

        with sqlite3.connect('network_devices.db') as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Check if MAC exists in db
            sql_query = '''SELECT id, ipv6_address
                FROM devices
                WHERE mac_address LIKE ?;'''
            data_tuple = (host['mac'],)
            logging.debug(f'MAC: {host["mac"]}')
            c.execute(sql_query, data_tuple)

            # Check if device was found.
            # If result, then it exists.
            try:
                result = c.fetchone()
                logging.info('Device exists in database.')
            except Exception as e:
                #result = 0
                logging.info('Device not found in db.')

            if result:
                # Update it with new addr.
                # Check if new addr is already in the data first. If not, then append it.
                # Load current data
                device_id = result['id']
                logging.debug(f'Device ID: {device_id}')
                ipv6_addrs = result['ipv6_address']
                if ipv6_addrs:
                    try:
                        current_ipv6_addrs = json.loads(result['ipv6_address'])
                    except json.JSONDecodeError:
                        current_ipv6_addrs = []
                else:
                    current_ipv6_addrs = []


                logging.debug(f'Current IPv6 addrs for device: {current_ipv6_addrs}')

                # If addr not in current data, append it:
                if not host['ip'] in current_ipv6_addrs:
                    current_ipv6_addrs.append(host['ip'])
                    new_data_json = json.dumps(current_ipv6_addrs)
                else:
                    new_data_json = json.dumps(current_ipv6_addrs)

                sql_query = '''UPDATE devices
                    SET ipv6_address = ?
                    WHERE id = ?;'''
                data_tuple = (new_data_json, device_id)

                logging.debug(f'IP to write: {new_data_json}')

                c.execute(sql_query, data_tuple)
            else:
                # Add it if it doesn't exist
                sql_query = '''INSERT INTO devices (mac_address, ipv6_address, ip_address) 
                    VALUES (?, ?, ?);
                '''

                ipv6_list = [host['ip']]
                ipv6_json = json.dumps(ipv6_list)

                data_tuple = (host['mac'], ipv6_json, 0)
                c.execute(sql_query, data_tuple)

            conn.commit()
        conn.close()

    # If it exists, update it with IPv6 addr. 
    # If already has one, then load current data as list, append new one, and write back.

def add_to_database(hosts) -> None:
    ''' Add given discovered-hosts to database. '''

    #

    # Connect to db + create cursor
    with sqlite3.connect('network_devices.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Loop through the discovered hosts
        for host in hosts:
            ip_version = ipaddress.ip_address(host['ip']).version

            # Separate v4 and v6 addrs - v6 too big to save as int
            #if ipaddress.ip_address(host['ip']).version == 6:
            if ip_version == 6:
                host_ipv6 = host['ip']
                host_ipv4 = '0.0.0.0'
            #elif ipaddress.ip_address(host['ip']).version == 4:
            elif ip_version == 4:
                host_ipv6 = '::'
                host_ipv4 = host['ip']


            # Check if MAC already exists in db
            c.execute('''SELECT id 
                FROM devices 
                WHERE mac_address LIKE ?''', 
                (host['mac'],)
            )
            try:
                result = c.fetchone()[0]
            except Exception as e:
                result = 0
                logging.info(f'Device does not appear to be in database: {str(e)}')

            # If it exists, update it.
            # Save IPs as integer, for sorting purpose.
            if result:
                logging.info(f'Updating existing record {result}...')
                """
                # # # OLD VERSION. TESTING BELOW for separate ip versions
                c.execute('''UPDATE devices
                    SET hostname = ?, ip_address = ?, mac_address = ?, ipv6_address = ?
                    WHERE id = ?;''',
                    #(host['hostname'], int(ipaddress.ip_address(host['ip'])), host['mac'], result)
                    (host['hostname'], int(ipaddress.ip_address(host_ipv4)), host['mac'], host_ipv6, result)
                ) # # # END OLD VERSION
                """

                ### NEW VERSION (TESTING)- don't overwrite existing values, or write junk values.
                # Instead just skip that value. Make 2 versions; 1 for v4 and one for v6
                if ip_version == 4:
                    c.execute('''UPDATE devices
                        SET hostname = ?, ip_address = ?
                        WHERE id = ?;''',
                        (host['hostname'], int(ipaddress.IPv4Address(host_ipv4)), result)
                        )

                elif ip_version == 6:
                    deviceid = result
                    logging.info(deviceid)
                    c.execute('SELECT ipv6_address FROM devices WHERE id = ?;', (deviceid,))
                    old_ipv6_data = c.fetchone()[0]
                    try:
                        ipv6_data = json.loads(old_ipv6_data)
                    except TypeError: #If it's null/none
                        ipv6_data = []

                    if host_ipv6 not in ipv6_data:
                        ipv6_data.append(host_ipv6)
                    ipv6_json = json.dumps(ipv6_data)

                    sql_query = '''UPDATE devices
                        SET hostname = ?, ipv6_address = ?
                        WHERE id = ?;
                    '''
                    data_tuple = (host['hostname'], ipv6_json, result)
                    c.execute(sql_query, data_tuple)

                ### END NEW VERSION

            # If MAC not in db, add it.
            else:
                """
                # # # OLD VERSION - replace with separate v4 + v6 versions
                logging.info(f'Adding device with mac {host["mac"]} to database...')
                c.execute('''
                    INSERT INTO devices (hostname, ip_address, mac_address, ipv6_address)
                    VALUES (?, ?, ?, ?)
                    ''',
                    #(host['hostname'], int(ipaddress.ip_address(host['ip'])), host['mac'])
                    (host['hostname'], int(ipaddress.ip_address(host_ipv4)), host['mac'], json.dumps([host_ipv6]))
                )
                # # # END OLD VERSION
                """
                 # Add host to db, with either v4 or v6 addr
                if ip_version == 4:
                    c.execute('''
                        INSERT INTO devices (hostname, ip_address, mac_address)
                        VALUES (?, ?, ?)
                        ''',
                        (host['hostname'], int(ipaddress.ip_address(host_ipv4)), host['mac'])
                    )
                elif ip_version == 6:
                    c.execute('''
                        INSERT INTO devices (hostname, mac_address, ipv6_address)
                        VALUES (?, ?, ?)
                        ''',
                        (host['hostname'], host['mac'], json.dumps([host_ipv6]))
                    )

        # Commit changes and close connection
        conn.commit()
    conn.close()

def get_v6_prefixes() -> set:
    '''Return all IPv6 prefixes on local interface.'''
    #Get all local prefixes
    prefixes = set()
    for x in scapy.conf.iface.ips[6]:
        private = ipaddress.IPv6Address(x).is_private
        prefix = ipaddress.IPv6Network(x).supernet(new_prefix=64)
        #logging.debug(f'Private: {private} | {prefix}')
        prefixes.add(prefix)

    all_prefixes = {format(x): x.is_private for x in prefixes}

    return prefixes

## Testing. Separating hostname resolution into its own function so I can thread it later.
def resolve_hostname(host, index, hosts, lock):
    ''' Resolve a single hostname. '''
    try:
        hostname = socket.gethostbyaddr(host['ip'])[0]
        #logging.debug(f'Hostname: {host["hostname"]}\n')
        logging.info(hostname)
    except socket.herror as e:
        # Couldn't get hostname
        logging.error(f'{str(e)}')
        hostname = ''

    # Update hostname in dict safely
    with lock:
        hosts[index]['hostname'] = hostname


def main(ip_range, progress_callback=None, stop_event=None, interface=None) -> None:
    ''' Main. 
    Initialize database, then run ARP scan, then resolve hostnames for any found devices, 
    and finally save device details to database. '''

    # Clear stop event if passed, otherwise will immediately stop.
    if stop_event:
        stop_event.clear()

    # Initialize db first
    initialize_db()

    ## Scan the network for hosts

    # If address is v4, do ARP scan; if v6, do NDP scan
    ip_version = ipaddress.ip_network(ip_range, strict=False).version

    if ip_version == 4:
        #hosts = arp_scan(ip_range, progress_callback)
        # TESTING MULTI-THREADED VERSION
        hosts = arp_scan_threaded(ip_range, progress_callback, stop_event, interface)
    elif ip_version == 6:
        hosts = ndp_scan(ip_range, progress_callback)

    if hosts:
        total_hosts = len(hosts)
    else:
        logging.warning('Either stopped early, no hosts found or an error occured.')
        progress_callback(0, 0, 'Scan interrupted.', 'stop')
        return

    if progress_callback:
        progress_callback(0, total_hosts, 'Resolve hostnames..', 'determinate')

    # # # for NEW threaded hostnames - TESTING
    lock = threading.Lock()
    threads = []
    # # #

    # Loop through the discovered hosts and resolve their hostnames
    for i, host in enumerate(hosts):
        # Check if stop event is set, and stop if so.
        if stop_event:
            if stop_event.is_set():
                logging.warning('Stopping hostname resolution.. (stop event set)')
                return

        '''
        # Use the IP address to get the hostname
        logging.debug(host['ip'])
        try:
            host['hostname'] = socket.gethostbyaddr(host['ip'])[0]
            logging.debug(f'Hostname: {host["hostname"]}\n')
        except socket.herror as e:
            logging.debug(f'{str(e)}')
            host['hostname'] = ''
        '''

        # # # NEW: Try resolving hostnames concurrently in threads?
        hostname_thread = threading.Thread(target=resolve_hostname, args=(host, i, hosts, lock))
        threads.append(hostname_thread) #will join() them later
        hostname_thread.start()
        # # #

        # Increment progress counter
        if progress_callback:
            progress_callback(i + 1, total_hosts, f'Resolve hostnames: {host["ip"]}', 'determinate')


    # # # NEW THREADED
    # NOTE: Increment progress counter when a thread finishes? If possible. Instead of the above which is super fast now.
    for thread in threads:
        thread.join()
    logging.info('Waiting for hostname resolution...')
    # # #


    # Add the discovered hosts to the database
    if hosts:
        add_to_database(hosts)

    logging.info('Finished scan.')


# This module shouldn't be run as a script, but sometimes I do with an odd function here anyways, so.
if __name__ == "__main__":
    # Initialize db before doing anything that needs it.
    initialize_db()

    # Run IP or ARP sniffer indefinitely, and save results to db.
    #sniff_arp()
    #sniff_ipv6()
    #tcp_syn_scan('10.0.0.1')
