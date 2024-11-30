#!/usr/bin/env python3

import sqlite3
import socket
import wakeonlan
import ipaddress
import scapy.all as scapy
import threading
from tkinter import *
from tkinter import ttk, messagebox
import json
import logging

# Other modules
import scan

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# WoL packets are send to the broadcast addr, to ask if any machine has given MAC
DEFAULT_NETMASK = 24 #Used for sending WoL packet, to calculate dest broadcast addr

# Start using a lock with any db functions
lock = threading.Lock()

'''
def get_ip() -> str:
    """ Get and return IP, by initiating a remote connection. """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('1.1.1.1', 80))
    _local_ip = s.getsockname()[0]
    s.close()
    return _local_ip
'''

def get_local_ips() -> list:
    ''' Return a list of the machine's IP addrs. '''
    return socket.gethostbyname_ex(socket.gethostname())[-1]

def get_local_ips_scapy() -> list:
    ''' Return a list of IP addrs for each interface that has one. '''
    return [scapy.conf.ifaces[x].ip for x in scapy.conf.ifaces if scapy.conf.ifaces[x].ip]

def get_local_interfaces() -> dict:
    ''' Return a dict containing name of each interface along with its IPv4 addr.'''
    local_interfaces = {}
    for _ in scapy.conf.ifaces:
        if scapy.conf.ifaces[_].ip: #Only list interfaces that have an associated ip addr
            local_interfaces[scapy.conf.ifaces[_].name] = scapy.conf.ifaces[_].ip
    return local_interfaces

#print(get_local_interfaces())

def write_hostname(hostname: str, i_d: str) -> None:
    ''' Write discovered hostname to db. '''
    logging.debug(f'ID: {type(i_d)} / Hostname: {type(hostname)}')
    with lock:
        with sqlite3.connect('network_devices.db') as conn:
            c = conn.cursor()
            sql_query = '''UPDATE devices SET hostname = ? WHERE id = ?;'''
            data_tuple = (hostname, i_d)
            c.execute(sql_query, data_tuple)
            conn.commit()
        conn.close()

""" #Replacing with write_ping_by_id() below
def write_ping_to_db(ip_addr, version, resp_time) -> bool:
    ''' Add/update a ping response time in the devices database. '''
    with sqlite3.connect('network_devices.db') as conn:
        c = conn.cursor()

        match version:
            case 4:
                sql_query = '''UPDATE devices
                    SET ping_time = ?
                    WHERE ip_address = ?
                '''
            case 6:
                sql_query = '''UPDATE devices
                    SET ping_time = ?
                    WHERE ipv6_address = ?
                '''

        data_tuple = (resp_time, ip_addr)
        c.execute(sql_query, data_tuple)

        conn.commit()
    conn.close()
"""

def write_ping_by_id(dev_id, resp_time) -> None:
    ''' Add/update a single ping response time in the database (where id=?). '''
    with lock:
        with sqlite3.connect('network_devices.db') as conn:
            c = conn.cursor()

            # New version using ID
            sql_query = '''UPDATE devices
                        SET ping_time = ?
                        WHERE id = ?;
                    '''

            logging.debug(f'device ID to write: {dev_id}')
            data_tuple = (resp_time, dev_id)
            c.execute(sql_query, data_tuple)

            conn.commit()
        conn.close()

# Stop event for sniffer threads.
STOP_EVENT = threading.Event() #Pass as stop_filter for scapy.sniff

class MainWindow():
    ''' Class for the GUI. '''
    def __init__(self):
        btn_pad = 4 #use to style widgets
        fontn = ('Cascadia Code', 8)
        #fontn = ('Fira Code', 8)
        font_title = ('Aldrich', 10)
        emerald = '#42e68c'
        transparent_color = '#123456'

        self.root = Tk()
        self.root.title('N.E.T.R.A.I.D.E.R.')
        self.root.maxsize(2160,2560)
        #self.root.wm_attributes('-transparentcolor', transparent_color)

        # import the forest-dark.tcl file
        #self.root.tk.call("source", "Forest-ttk-theme-1.0/forest-dark.tcl")
        self.root.tk.call("source", "theme/forest-dark.tcl")

        s = ttk.Style()
        s.theme_use('forest-dark')
        s.configure('.', font=fontn)
        s.configure('Treeview.Heading', font=font_title)

        # Configure row/column sizes
        for i in range(4): # Keep all 4 columns even width
            self.root.columnconfigure(i, weight=1, uniform='col')
        for i in range(12): # Even height for all rows
            self.root.rowconfigure(i, weight=1, uniform='row')
        for i in range(1, 5): #For the treeview- make rows a little taller to give it room
            self.root.rowconfigure(i, weight=3, uniform='row')

        # Create a frame for the device list
        #self.device_frame = ttk.Frame(self.root)
        #self.device_frame.grid(row=0, column=0, columnspan=4, sticky='wens')

        # Title image widget
        self.title_image = PhotoImage(file='logo.png')
        self.image_label = Label(image=self.title_image)
        self.image_label.grid(row=0, column=0, columnspan=2, sticky='wns', padx=btn_pad, pady=btn_pad)

        # Extended name on top right corner
        self.subtitle_label = ttk.Label(self.root, 
            text='Network Exploration, Tracking, and Remote Activation Interface\nwith Dark-mode for Efficient Reconnaissance',
            font=(font_title[0], fontn[1]-2),
            justify='right')
        self.subtitle_label.grid(row=0, column=2, columnspan=2, sticky='ens', padx=btn_pad, pady=btn_pad)

        # Create a tree view to display the device list
        self.tree = ttk.Treeview(self.root, show='headings')
        self.tree["columns"] = ('id', "hostname", "ip_address", "mac_address", "ip_int", "ipv6_address", "ping_time", "ports")
        self.tree.column("#0", width=40, anchor=W, minwidth=24)
        self.tree.column('id', anchor=W, width=24)
        self.tree.column("hostname", anchor=W, stretch=True, minwidth=60, width=128)
        self.tree.column("ip_address", anchor=W, stretch=True, minwidth=80, width=128)
        self.tree.column("mac_address", anchor=W, stretch=True, minwidth=64, width=144)
        self.tree.column("ip_int", anchor=W, stretch=False, minwidth=0, width=0)
        self.tree.column("ipv6_address", anchor=W, stretch=True, minwidth=96, width=192)
        self.tree.column("ping_time", anchor=W, minwidth=64, width=80, stretch=True)
        self.tree.column("ports", anchor=W, stretch=True)
        # Tree headings
        self.tree.heading("#0", text="ID", anchor=W)
        self.tree.heading("id", text='ID', anchor=W)
        self.tree.heading("hostname", text="Hostname", anchor=W)
        self.tree.heading("ip_address", text="IP Addr", anchor=W)
        self.tree.heading("mac_address", text="MAC Addr", anchor=W)
        self.tree.heading("ip_int", text="IP (int)", anchor=W)
        self.tree.heading("ipv6_address", text="IPv6 Addr", anchor=W)
        self.tree.heading("ping_time", text="Ping (ms)", anchor=W)
        self.tree.heading('ports', text='Ports', anchor=W)

        self.tree.grid(row=1, column=0, columnspan=4, rowspan=4, sticky='wens', padx=btn_pad, pady=btn_pad)

        # Bind the header click event to the sort function
        for col in self.tree["columns"]:
            self.tree.heading(col, command=lambda c=col: self.sort_treeview(c, False))

        # Create a button to send WoL
        self.wol_button = ttk.Button(self.root, text="Send WoL Packet", command = lambda: MainWindow.send_wol(self), style='Accent.TButton')
        self.wol_button.grid(row=5, column=0, rowspan=2, columnspan=2, sticky='news', padx=btn_pad, pady=btn_pad)

        # Scan button
        self.scan_button = ttk.Button(self.root, text = 'Scan network', command = self.scan_button_callback)
        self.scan_button.grid(row=5, column=2, columnspan=2, sticky='news', padx=btn_pad, pady=btn_pad)

        # Combobox to select which IP to scan from
        self.local_ip_addresses = get_local_ips()
        self.ip_combobox = ttk.Combobox(self.root, values=self.local_ip_addresses)
        #self.ip_combobox.set('Network interface:')
        self.ip_combobox.set(self.local_ip_addresses[0])
        self.ip_combobox.grid(row=6, column=2, sticky='news', padx=btn_pad, pady=btn_pad)


        # Select netmask size
        self.netmask_spinbox = ttk.Spinbox(self.root, from_=0, to=128, wrap=True)
        self.netmask_spinbox.set('24')
        self.netmask_spinbox.grid(row=6, column=3, sticky='news', padx=btn_pad, pady=btn_pad)

        # ProgressBar
        self.scan_progress = IntVar()
        self.scan_progress_max = 100  # This will be updated dynamically
        self.progr_bar = ttk.Progressbar(self.root, variable=self.scan_progress, maximum=self.scan_progress_max)
        self.progr_bar.grid(row=7, column=0, columnspan=4, sticky='news', padx=btn_pad, pady=btn_pad)


        # Label to display text feedback
        self.feedback_text = StringVar() #Text variable for scan_label
        self.feedback_text.set('')
        self.scan_label = ttk.Label(self.root, textvariable = self.feedback_text, font=fontn)
        self.scan_label.grid(row=7, column=1, columnspan=2, sticky='ns', padx=btn_pad, pady=btn_pad)


        # Label for below ping target radios
        self.ping_target_label = ttk.Label(self.root, text='Ping target option:', font=fontn)
        self.ping_target_label.grid(row=8, column=2, sticky='wns', padx=btn_pad, pady=btn_pad)

        #Radios to select ping target (treeview selection OR input from text boxes)
        self.ping_target = IntVar()
        self.ping_target_0 = ttk.Radiobutton(self.root, text='Device selection', variable=self.ping_target, value=0)
        self.ping_target_1 = ttk.Radiobutton(self.root, text='Subnet entry', variable=self.ping_target, value=1)
        self.ping_target_0.grid(row=9, column=2, sticky='wns', padx=btn_pad, pady=btn_pad)
        self.ping_target_1.grid(row=10, column=2, sticky='wns', padx=btn_pad, pady=btn_pad)

        # Button to send ping
        self.ping_button = ttk.Button(self.root, text='Ping', command = self.ping_callback)
        self.ping_button.grid(row=8, column=3, sticky='news', padx=btn_pad, pady=btn_pad)

        # Testing combobox to select network interface
        self.interface_combobox_label = ttk.Label(text='Network interface:', font=fontn)
        self.interface_combobox_label.grid(row=11, column=2, sticky='ens', padx=btn_pad, pady=btn_pad)

        self.local_net_interfaces = [_ for _ in get_local_interfaces()]
        self.interface_combobox = ttk.Combobox(self.root, values=self.local_net_interfaces)
        self.interface_combobox.grid(row=11, column=3, columnspan=1, sticky='news', padx=btn_pad, pady=btn_pad)
        self.interface_combobox.bind("<<ComboboxSelected>>", self.get_interface_selection)

        # Sniffer buttons
        self.sniff_arp_btn = ttk.Button(self.root, text='Sniff - ARP', command=self.sniff_arp_callback)
        self.sniff_ip_btn = ttk.Button(self.root, text='Sniff - IP', command=self.sniff_ip_callback)
        self.sniff_ipv6_btn = ttk.Button(self.root, text='Sniff - IPv6', command=self.sniff_ipv6_callback)
        self.stop_sniff_btn = ttk.Button(self.root, text='STOP', command=self.sniff_stop_callback)

        self.sniff_arp_btn.grid(row=8, column=0, sticky='nswe', padx=btn_pad, pady=btn_pad)
        self.sniff_ip_btn.grid(row=9, column=0, sticky='nswe', padx=btn_pad, pady=btn_pad)
        self.sniff_ipv6_btn.grid(row=10, column=0, sticky='nswe', padx=btn_pad, pady=btn_pad)
        self.stop_sniff_btn.grid(row=11, column=0, sticky='nswe', padx=btn_pad, pady=btn_pad)
        # End sniffer buttons

        # "Resolve hostname" button
        self.hostname_btn = ttk.Button(self.root, text='Resolve hostname', command=self.resolve_selection_hostname)
        self.hostname_btn.grid(row=9, column=3, sticky='nswe', padx=btn_pad, pady=btn_pad)

        # "Port scan" button
        self.portscan_btn = ttk.Button(self.root, text='Port scan', command=self.port_scan_callback)
        self.portscan_btn.grid(row=10, column=3, sticky='nswe', padx=btn_pad, pady=btn_pad)


    #TESTING
    def get_interface_selection(self, event) -> None:
        ''' Get + print info of selected interface from interface_combobox. For testing/debugging. 
        Bind to ComboboxSelected event (i.e. when an item is selected) '''
        x = self.interface_combobox.get()
        # Print selection and its IP
        logging.debug(x)
        logging.debug(scapy.conf.ifaces.dev_from_name(x).ip)

    def port_scan_callback(self) -> None:
        ''' Run port scan (TCP SYN scan) against selected device. '''

        # Clear stop event if set, otherwise will stop right away.
        if STOP_EVENT.is_set():
            STOP_EVENT.clear()

        def port_scan_thread(dev_id, dev_ip) -> None:
            ''' Execute the port scan. Run this as a daemon thread. '''
            open_ports = scan.tcp_syn_scan(dev_ip, self.progress_callback, STOP_EVENT)
            logging.info('Saving ports data...')
            scan.write_ports_by_id(dev_id, open_ports, lock)
            logging.info('Finished.')
            # update progress bar
            self.feedback_text.set(f'Port scan finished.')
            self.update_device_list()

        selected_items = self.tree.selection()
        if selected_items:
            for selected_item in selected_items:
                dev_id = self.tree.item(selected_item, 'values')[0]
                dev_ip = self.tree.item(selected_item, 'values')[2]
                # If no IPv4 addr (i.e. addr is 0.0.0.0) then check for v6
                if dev_ip == '0.0.0.0':
                    dev_ip = json.loads(self.tree.item(selected_item, 'values')[5])[0]

                tcp_port_scan_thread = threading.Thread(target=port_scan_thread, args=(dev_id, dev_ip), daemon=True)
                tcp_port_scan_thread.start()
        else:
            messagebox.showerror('Error', 'No item selected.')

    def resolve_selection_hostname(self) -> None:
        ''' Get hostname of selected tree item. '''
        selected_items = self.tree.selection()
        if selected_items:
            self.feedback_text.set(f'Resolve {len(selected_items)} hostname(s)... (0/{len(selected_items)})')
            self.scan_progress.set(0)
            self.progr_bar['maximum'] = len(selected_items)

            def hn_thread():
                for idx, selected_item in enumerate(selected_items):
                    i_d = self.tree.item(selected_item, "values")[0]
                    ip_addr = self.tree.item(selected_item, "values")[2]
                    # If no IPv4 addr, try IPv6
                    if not ip_addr or ip_addr == '0.0.0.0':
                        ip_addr = self.tree.item(selected_item, "values")[5]
                    # Lookup hostname
                    try:
                        hostname = socket.gethostbyaddr(ip_addr)[0]
                    except socket.herror as e:
                        hostname = None

                    logging.info(f'ID: {i_d} / Hostname: {hostname}')

                    #Write hostname to db if successful
                    if hostname:
                        logging.info('Writing to database...')
                        write_hostname(hostname, i_d)

                    # Update progress bar + text
                    self.feedback_text.set(f'Resolve {len(selected_items)} hostname(s)... ({idx+1}/{len(selected_items)})')
                    self.scan_progress.set(idx+1)

                # Finished - update progress bar
                self.feedback_text.set(f'Resolve {len(selected_items)} hostnames - FINISHED')
                self.update_device_list()
                logging.info('Done.')

            hn_thread = threading.Thread(target=hn_thread, daemon=True)
            hn_thread.start()
        # Display error message if no device selected
        else:
            messagebox.showerror('Error', 'No item selected.')

    def send_wol(self) -> bool:
        ''' Get selected item and send WoL packet. 
        Return True if sent successfully, else False. '''
        #selected_item = self.tree.focus()  # Get the selected item
        # tree.selection will return more than 1 selection unlike tree.focus
        selected_items = self.tree.selection()

        if selected_items:
            for selected_item in selected_items:
                mac_address = self.tree.item(selected_item, "values")[3]
                device_id = self.tree.item(selected_item, "values")[0]
                logging.debug(f'device id: {device_id}')

                # Try to figure out whether the device has a IPv4 or IPv6 address
                # Try v4 first, then if not one, check IPv6 data
                try:
                    # Try v4 first:
                    ip_addr = ipaddress.IPv4Address(self.tree.item(selected_item, "values")[2])
                    logging.debug(f' ip_addr (v4): {ip_addr}')
                    logging.debug(f'type: {type(ip_addr)}')
                    logging.debug(f'version: {ip_addr.version}')
                    # If no v4 addr, try v6:
                    if format(ip_addr) == '0.0.0.0':
                        logging.debug('No v4 addr, trying v6...')
                        ip_addr = ipaddress.IPv6Address(scan.get_ipv6_by_id(device_id)[-1]) #Using last addr in returned list [-1]
                        logging.debug(f'ip_addr (v6): {ip_addr}')
                except Exception as e:
                    logging.error(f'Bad or missing ip? For device #{device_id}')
                    messagebox.showerror('Error', f'{str(e)}')
                    return False

                # Set broadcast addr based on v4 or v6
                match ip_addr.version:
                    case 4:
                        # Get the broadcast addr from the IP. Assume /24 until I improve this.
                        ip_addr_cidr = ipaddress.ip_network(ip_addr, strict=False) # /32
                        broadcast_addr = str(ip_addr_cidr.supernet(new_prefix=DEFAULT_NETMASK)[-1])
                    case 6:
                        # all nodes multicast
                        broadcast_addr = 'FF02::1'

                # If not a RFC1918 private address, confirm.
                if not ip_addr.is_private:
                    cont = messagebox.askokcancel('Info', 'Address is not RFC1918 private, continue?')
                    if not cont:
                        #return False
                        logging.warning(f'Skipping device {mac_address}')
                        continue

                # Send magic packet to broadcast addr
                try:
                    wakeonlan.send_magic_packet(mac_address, ip_address=broadcast_addr)
                    messagebox.showinfo("Success",
                        f'Wake-on-lan packet sent successfully.\n\nMAC: {mac_address}\nBroadcast IP: {broadcast_addr}')
                    continue
                except Exception as e: 
                    # If exception, show error and return
                    messagebox.showerror("Error", f"Failed to send wake-on-lan packet: {str(e)}")
                    return False
            # After looping through each selected item, return
            return True
        else:
            # If no item selected, show error
            messagebox.showerror('Error', 'No item selected.')
            logging.warning('No item selected to send WoL.')
            return False

    def populate_device_list(self) -> None:
        ''' Read the database and populate the treeview with the contents. '''
        with lock:
            with sqlite3.connect('network_devices.db') as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                try:
                    c.execute('''
                        SELECT *
                        FROM devices
                        ORDER BY ip_address
                    ''')
                except sqlite3.OperationalError as e:
                    messagebox.showerror('Warning', 'No devices in database. Perform initial ARP/NDP scan or packet sniff to populate devices view.')

                # Insert results into the treeview
                for device in c.fetchall():
                    self.tree.insert("",
                        "end",
                        text=device['id'],
                        values=(device['id'], device['hostname'], ipaddress.ip_address(int(device['ip_address'])), device['mac_address'], device['ip_address'], device['ipv6_address'], device['ping_time'], device['ports']),
                    )
            conn.close

    def update_device_list(self) -> None:
        ''' Update device list with current database contents. '''
        # Clear existing contents,
        for item in self.tree.get_children():
            self.tree.delete(item)
        # and re-populate the treeview.
        self.populate_device_list()
        self.root.update_idletasks()

    def ping_callback(self) -> None:
        ''' Callback for 'ping' button. 
        Get the selected target host(s)/subnet (from either treeview device selection or subnet input fields), '''
        # Target = radio button selection; either treeview selection OR subnet input field.
        # If target is subnet input field, then ping all IPs in the subnet.
        _target = self.ping_target.get()
        _interface = self.interface_combobox.get()
        devs_to_ping = [] #list of dicts; dict contain id+ip

        ## 0 = treeview selection, 1 = subnet (text) entry fields ##
        match _target:
            case 0:
                # Read treeview selection and use values of ip_address column
                selected_items = self.tree.selection()
                ip_addrs = [] #IP addrs to ping

                for i, item in enumerate(selected_items):
                    selected_item = self.tree.item(selected_items[i])
                    values = selected_item['values']
                    ip_addr = values[2]
                    dev_id = values[0]
                    # If no ipv4 addr (i.e. saved as 0.0.0.0) then use IPv6 addr
                    if ip_addr == '0.0.0.0':
                        # get ipv6 addr
                        ip_addr = scan.get_ipv6_by_id(dev_id)[-1] #Get the last v6 addr
                    # NOTE: Need to use a dict (or list of dicts) instead of list, and include dev_id.
                    # Using a list will only work if there's only 1 selected item.
                    ip_addrs.append(ip_addr)
                    devs_to_ping.append({'id': dev_id, 'addr': ip_addr})

            case 1:
                # Read input from subnet input Entry boxes
                subnet_cidr = f'{self.ip_combobox.get()}/{self.netmask_spinbox.get()}'
                # Validate + Show error if invalid subnet
                try:
                    _net = ipaddress.ip_network(subnet_cidr, strict=False)
                except Exception as e:
                    messagebox.showerror('Error', 
                    f'Subnet input is probably invalid. \n\nThe following exception occured while attempting to create an instance of ipaddress.ip_network(subnet_cidr, strict=False): \n\n{str(e)}',
                    )
                    logging.error(f'{str(e)}')
                    return

                ip_addrs = [format(host) for host in _net.hosts()]
                for _ in ip_addrs:
                    devs_to_ping.append({'id': 0, 'addr': _})

        logging.info(f'IP addrs to ping: {ip_addrs}')

        def ping_thread() -> None:
            ''' Run scan.ping_host. This Should be called as a daemon thread. '''
            # Clear stop event, if set. Otherwise, if previously set, then ping will immediately stop.
            if STOP_EVENT.is_set():
                STOP_EVENT.clear()

            results = scan.ping_host(ip_addrs, self.progress_callback, _interface, STOP_EVENT)
            logging.debug(f'results dict: {results}')

            # Save results to db
            for i, ping_result in enumerate(results):
                # # # NEW version of write, using ID# instead of ip addr, to stop inserting/updating duplicate devices.
                device_id = devs_to_ping[i]['id']
                write_ping_by_id(device_id, results[ping_result])

            # Update treeview to represent new results
            self.update_device_list()
            logging.info('Results saved to db.')

            # Update text on label
            self.feedback_text.set(f'Received response from {len(results)} hosts')
            self.root.update_idletasks()

        ping_thread = threading.Thread(target=ping_thread, daemon=True)
        ping_thread.start()

    def scan_button_callback(self) -> None:
        '''Callback method for "scan network" button. 
        Launch scan.main (ARP scan) in a separate thread, then update treeview.'''
        #cidr_input = self.cidr_entry.get()
        subnet_cidr = f'{self.ip_combobox.get()}/{self.netmask_spinbox.get()}'
        # Show error if invalid subnet
        try:
            _net = ipaddress.ip_network(subnet_cidr, strict=False)
        except Exception as e:
            messagebox.showerror('Error', str(e))
            logging.error(f'{str(e)}')
            return

        # Discourage IPv6 scan if attempted, but do it if sure.
        if _net.version == 6:
            cont = messagebox.askokcancel('Warning', 'Scanning IPv6 subnet in this manner is discouraged. \nContinue anyways?')
            if not cont:
                return

        # Set progress bar max
        self.scan_progress_max = _net.num_addresses
        self.progr_bar['maximum'] = self.scan_progress_max

        logging.info(f'Scanning range of {_net.num_addresses} addresses.')

        # Confirmation dialog if huge range to scan
        if _net.num_addresses >= 16384:
            cont = messagebox.askokcancel('Confirm large range', f'IP range includes {_net.num_addresses} addresses. This may take a long time. Continue?')
            if not cont:
                return

        ''' # 10-5-24 commenting this out. this was already abandoned for the newer callback. make sure nothing else is using it before deleting.
        def progress_callback(progress, total, msg, _mode):
            # Callback to update progress bar
            match _mode:
                case 'determinate':
                    self.progr_bar['mode'] = _mode
                    self.scan_progress.set(progress)
                    self.progr_bar['maximum'] = total
                    self.feedback_text.set(f'{msg} ({progress}/{total})')
                    self.root.update_idletasks()
                case 'indeterminate':
                    if total == 999:
                        self.progr_bar.stop()
                        self.progr_bar['mode'] = 'determinate'
                    else:
                        self.progr_bar['mode'] = 'indeterminate'
                        self.progr_bar['maximum'] = 20
                        self.progr_bar.start(500)
                        self.feedback_text.set(f'{msg}')
                        self.root.update_idletasks()
                case 'stop':
                    self.progr_bar.stop()
                    self.progr_bar['mode'] = 'determinate'
                    '''

        def scan_thread():
            ''' Should be launched as a daemon thread. Run scan.main, then update device list in treeview. '''
            scan.main(subnet_cidr, self.progress_callback, STOP_EVENT, self.get_selected_interface())
            self.update_device_list()
            # Update text on label
            self.feedback_text.set('Finished scan.')
            self.root.update_idletasks()

        self.feedback_text.set('Scan for devices...')
        self.root.update_idletasks()
        # Run ARP scan from scan.py, as a daemon thread
        scan_thread = threading.Thread(target=scan_thread, daemon=True)
        scan_thread.start()


    ## PACKET SNIFFER CALLBACKS ##

    def sniff_arp_callback(self) -> None:
        ''' Launch ARP sniffer as a thread.'''

        def sniff_arp_thread_new():
            ''' Sniff for ARP packets indefinitely, on <interface>. Stop when STOP_EVENT is set. '''
            # STOP_EVENT passed to use as stop_filter for scapy.sniff
            STOP_EVENT.clear()
            scan.sniff_arp(STOP_EVENT, interface=self.get_selected_interface(), lock=lock)

        sniff_arp_thread = threading.Thread(target=sniff_arp_thread_new, daemon=True)
        sniff_arp_thread.start()

        # Show text on output bar
        self.feedback_text.set('Launched ARP sniffer.')
        self.root.update_idletasks()

    def sniff_ip_callback(self) -> None:
        ''' Launch IP sniffer as a thread. '''

        def sniff_ip_thread_new():
            ''' Sniff for ARP packets indefinitely, on <interface>. Stop when STOP_EVENT is set. '''
            # STOP_EVENT is passed, to use as stop_filter for scapy.sniff
            STOP_EVENT.clear()
            scan.sniff_ip(STOP_EVENT, interface=self.get_selected_interface(), lock=lock)

        sniff_ip_thread = threading.Thread(target=sniff_ip_thread_new, daemon=True)
        sniff_ip_thread.start()

        # Show text on output bar
        self.feedback_text.set('Launched IP sniffer.')
        self.root.update_idletasks()

    def sniff_ipv6_callback(self) -> None:
        ''' Launch v6 IP sniffer as a thread. '''
        def sniff_ipv6_thread():
            STOP_EVENT.clear()
            scan.sniff_ipv6(STOP_EVENT, interface=self.get_selected_interface())

        sniff_ipv6_thread = threading.Thread(target=sniff_ipv6_thread, daemon=True)
        sniff_ipv6_thread.start()

        # Text for status bar
        self.feedback_text.set('Started IPv6 sniffer.')
        self.root.update_idletasks()

    def sniff_stop_callback(self) -> None:
        ''' Stop sniffing. Any sniff/scan threads will check for STOP_EVENT to be set. '''
        #self.STOP_SNIFFING = True
        STOP_EVENT.set()
        logging.info('Stopping any running sniffer/scan ...')
        self.feedback_text.set('Stopping any running sniff/scan.')
        self.update_device_list()

    ## End sniffer callbacks ##

    def set_height(self) -> None:
        ''' Set window geometry. Height based on # of child items in treeview. '''
        heighty = int(len(self.tree.get_children())) * 24 + 48
        min_height = 750
        self.root.geometry(f'880x{max(min_height,heighty)}')

    def delete_item(self) -> None:
        ''' Delete selected treeview item. Bind to delete key. Does not remove item from database. '''
        selected_items = self.tree.selection()
        cont = messagebox.askokcancel('Confirm Deletion', f'Are you sure you want to delete {[self.tree.item(_, "values")[3] for _ in selected_items]}')
        if not cont:
            return
        for item in selected_items:
            self.tree.delete(item)

    def sort_treeview(self, col, reverse) -> None:
        ''' Sort treeview contents by column. Bind to heading click event. '''
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_treeview(col, not reverse))


    def progress_callback(self, progress, total, msg, _mode) -> None:
        ''' Callback to update progress bar. Intended to be passed to other functions in scan.py 
        module when calling them, so they have a means to provide feedback. 
        Moved from scan_button_callback. 
        Args:
        progress: Current progress.
        total: Max progress.
        msg: Text to display on label.
        mode: progressbar mode- determinate/indeterminate, or "stop" to stop an indeterminate one that's been start()-ed. 
        '''

        match _mode:
            case 'determinate':
                self.progr_bar['mode'] = 'determinate'
                self.scan_progress.set(progress)
                self.progr_bar['maximum'] = total
                self.feedback_text.set(f'{msg} ({progress}/{total})')
                self.root.update_idletasks()
            case 'indeterminate':
                self.progr_bar['mode'] = 'indeterminate'
                self.progr_bar['maximum'] = 20
                self.progr_bar.start(500)
                self.feedback_text.set(f'{msg}')
                self.root.update_idletasks()
            case 'stop':
                # Use to stop an indeterminate one that's been start()-ed
                self.progr_bar.stop()
                self.progr_bar['mode'] = 'determinate'

    def get_selected_interface(self) -> str:
        ''' Get+return selected network interface (name) from interface combobox. '''
        _ = self.interface_combobox.get()
        return _

# good ol' mainloop
if __name__ == '__main__':
    scan.initialize_db()
    gui = MainWindow()
    gui.populate_device_list()
    gui.set_height()
    gui.root.bind('<Delete>', lambda event:gui.delete_item())
    gui.root.mainloop()
