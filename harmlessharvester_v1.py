#!/usr/bin/env python
# Version 1.0.1
import sys, os, socket, time, getpass, threading, argparse
from datetime import datetime, timedelta
from logging import getLogger, ERROR
from Tkinter import *
from ttk import *
getLogger('scapy.runtime').setLevel(ERROR)

try:
    from scapy.all import *
except ImportError:
    print('[Error] Python-Scapy Installation Not Found')
    try:
        os.system("sudo apt-get install python-scapy -y")
        print('\t[*] Scapy now installed, please try again')
        sys.exit(0)
    except Exception as e:
        print("[ERROR] Cannot install python-scapy! - %s" % e)
        sys.exit(1)

# Check if root, root is required!
if not getpass.getuser() == 'root':
    print('[ERROR] Must run as root to read traffic'); sys.exit(1)

from src.read_config import *

class MainWindow(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title(string = 'Harmless Harvester - HTTP traffic dump')
        self.resizable(0,0)
        #self.style = Style()
        #self.style.theme_use("clam")
        self.configure(background = 'black')
        icon = PhotoImage(file='icon.png')
        self.tk.call('wm', 'iconphoto', self._w, icon)

        self.options = {
            'interface' : StringVar(),
        }

        settings = LabelFrame(self, text = 'Data')
        settings.grid(row = 0, column = 1, columnspan = 4)

        photo = PhotoImage(file='icon.png')
        #photo = photo.zoom(2)
        photo = photo.subsample(2)
        label = Label(self, image=photo, background = 'black')
        label.image = photo # keep a reference!
        label.grid(row = 0, column = 3)

        label2 = Label(self, image=photo, background = 'black')
        label2.image = photo # keep a reference!
        label2.grid(row = 0, column = 1)

        Label(settings, text = 'Interface').grid(row = 0, column = 1)
        Entry(settings, textvariable = self.options['interface'], width = 30).grid(row = 0, column = 2)

        result_frame = LabelFrame(self, text = 'Log', height = 400, width = 1400)
        result_frame.grid(row = 1, column = 1, columnspan = 3)

        Label(result_frame, text = 'Log frame').grid(row = 0, column = 1)
        self.options['result'] = Listbox(result_frame, width = 170, height = 30)
        self.options['result'].grid(row = 1, column = 1)
        #self.options['result'].bind("<Double-Button-1>", self.drop_to_shell)

        run = Button(result_frame, text = 'Run...', command = self.start_thread, width = 50).grid(row = 2, column = 1)

    HARVESTER = []

    def CLEAR_HARVESTER():
        global HARVESTER
        while 1:
            HARVESTER = []
            #print('Harvester cleared')  # Debug
            time.sleep(60)

    # Start Background thread for cooldowns
    harvester_timer = threading.Thread(target=CLEAR_HARVESTER)
    harvester_timer.daemon = True; harvester_timer.start()

    def dump(self):
        sniff(iface=self.options['interface'].get(), prn=self.check_pkt, store=0)

    def start_thread(self):
        # Start time thread
        run_thread = threading.Thread(target=self.dump)
        run_thread.daemon = True
        run_thread.start()

    def run(self):
        accounts = []
        if self.options['username'].get() and self.options['ufile'].get():
            accounts.append(self.options['username'].get())
            f = self.options['ufile'].get()
            for l in open(f).readlines():
                accounts.append(l)

        if not self.options['username'].get():
            f = self.options['ufile'].get()
            for l in open(f).readlines():
                accounts.append(l)
        else:
            accounts = [self.options['username'].get()]

        with tqdm(total=(len(accounts)), desc='Progress') as bar:
            for l in accounts:
                self.search(l.strip())
                bar.update(1)
                time.sleep(float('1.5'))

    def read_connection(self, pkt):
        # Read data on TCP port 80 only
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80 or pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                return True
            else:
                return False
        else:
            return False

    def check_pkt(self, pkt):
        global HARVESTER

        # If TCP 80 > Pass, else > Return
        if self.read_connection(pkt):
            pass
        else:
            return
        data = pkt[Raw].load

        # If data contains a link
        if 'Referer:' in data:
            link = data.split('\r') # Find hostname
            target = link[1].split(" ") # Get "just" the hostname
            if target[1] not in HARVESTER:
                HARVESTER.append(target[1])

                src = str(pkt[IP].src).strip() # Get source

                # Resolve hostname into IP address
                dst = ' >> ' + str(pkt[IP].dst).strip() # Get destination


                # Print result, depending on situation
                result = '[' + time_date() + ' ' + time_time() + "] %s" % src + "%s" % (dst).ljust(20) + "| Host: %s" % (target[1]).ljust(50)

                # The old output: Date > Time > Host > Dest > src
                # New output: Date > Time > Src > Dest > Host
                #result = '[' + time_date() + ' ' + time_time() + "] \033[1;92mHost: %s" % (target[1]).ljust(50) + "%s" % (dst).ljust(20) + "%s\033[0m" % src

                self.options['result'].insert(END, result)

                return
            else:
                return
        return

if __name__ == '__main__':
    panel = MainWindow()
    panel = mainloop()
