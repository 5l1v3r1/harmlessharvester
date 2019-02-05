#!/usr/bin/env python
# Version 1.0.1
import sys, os, time, getpass, threading, webbrowser, socket
from datetime import datetime, timedelta
from logging import getLogger, ERROR
from Tkinter import *
from ttk import *
import tkMessageBox
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
        self.title(string = 'Harmless Harvester - HTTP/HTTPS traffic dump')
        self.resizable(0,0)
        #self.style = Style()
        #self.style.theme_use("clam")
        self.configure(background = 'black')
        icon = PhotoImage(file='icon.png')
        self.tk.call('wm', 'iconphoto', self._w, icon)

        self.options = {
            'interface' : StringVar(),
        }

        global log
        global pwd
        global ssl
        log = False
        pwd = False
        ssl = False

        menu = Menu(self)
        filemenu = Menu(tearoff=False)
        mitm = Menu(tearoff=False)
        logging = Menu(tearoff=False)
        about = Menu(tearoff=False)
        menu.add_cascade(label="Sniffing", menu=filemenu)
        menu.add_cascade(label="MITM", menu=mitm)
        menu.add_cascade(label="Logging", menu=logging)
        menu.add_cascade(label="About", menu=about)

        # File dropdown
        filemenu.add_command(label="Start Sniffing", command=self.start_thread)
        filemenu.add_command(label="Dump SSL", command=self.ssl_sniff)
        filemenu.add_command(label="Clear log", command=self.clear_log)
        filemenu.add_command(label="Quit", command=self.quit)

        # MITM
        mitm.add_command(label="Targets", command=self.soon)
        mitm.add_command(label="Hosts", command=self.soon)

        # Logging
        logging.add_command(label="Save To File", command=self.save_file)
        logging.add_command(label="Write To File While Capturing", command=self.live_logging)
        logging.add_command(label="Password detection", command=self.password_detection)

        # About dropdown
        about.add_command(label="Twitter", command=self.open_twitter)
        about.add_command(label="GitHub", command=self.open_github)

        self.config(menu=menu)

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

        #run = Button(result_frame, text = 'Run...', command = self.start_thread, width = 50).grid(row = 2, column = 1)

    def clear_log(self):
        self.options['result'].delete(0, END)

    def save_file(self):
        filepath = './' + time.strftime('%d-%m-%Y_%H-%M-%S') + '.txt'
        with open(filepath, 'w+') as f:
            for line in self.options['result'].get(0, END):
                f.write(line + '\n')
            f.close()
        tkMessageBox.showinfo('INFO', 'File save to %s' % filepath)

    def live_logging(self):
        global log
        if log == True:
            log = False
            tkMessageBox.showinfo('INFO', 'Logging disabled')
        else:
            log = True
            tkMessageBox.showinfo('INFO', 'Logging enabled')

    def ssl_sniff(self):
        global ssl
        if ssl == True:
            ssl == False
            tkMessageBox.showinfo('INFO', 'SSL Sniffing disabled')
        else:
            ssl == True
            tkMessageBox.showinfo('INFO', 'SSL Sniffing enabled')

    def password_detection(self):
        global pwd
        if pwd == True:
            pwd = False
            tkMessageBox.showinfo('INFO', 'Password Detection disabled')
        else:
            pwd = True
            tkMessageBox.showinfo('INFO', 'Password Detection enabled')


    def open_twitter(self):
        webbrowser.open_new_tab('https://www.twitter.com/TheRealZeznzo')
    def open_github(self):
        webbrowser.open_new_tab('https://www.github.com/leonv024')

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

    def soon(self):
        tkMessageBox.showinfo("INFO", "Comming Soon! Please like and watch this github repo - Thank You")

    def dump(self):
        sniff(iface=self.options['interface'].get(), prn=self.check_pkt, store=0)

    def start_thread(self):
        # Start time thread

        if self.options['interface'].get() == '':
            tkMessageBox.showwarning("ERROR", "Please enter a interface to sniff with")
            return
        else:
            tkMessageBox.showinfo("INFO", "Sniffing started on interface: %s" % self.options['interface'].get())

        run_thread = threading.Thread(target=self.dump)
        run_thread.daemon = True
        run_thread.start()

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

        # If TCP 80 or TCP 443 > Pass, else > Return
        if self.read_connection(pkt):
            pass
        else:
            return

        data = pkt[Raw].load

        # Dump src and dst for SSL and HTTP
        src = pkt[IP].src
        dst = ' >> ' + pkt[IP].dst

        if dst not in HARVESTER:
            HARVESTER.append(dst)

            try:
                host = socket.gethostbyaddr(pkt[IP].dst)[0] # Try to resolve host
            except Exception:
                host = 'Failed to resolve host' # Error of failed and continue

            result = '[' + time_date() + ' ' + time_time() + "] %s" % src + "%s" % (dst).ljust(20) + "| Host: %s" % (host).ljust(50)

            self.options['result'].insert(END, result)
            self.options['result'].yview(END)



        if pwd == True:
            if 'password' in data:
                print('Password detected!\n--------------------\n%s' % data)

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
                self.options['result'].yview(END)

                if log == True:
                    filepath = time.strftime('%d-%m-%Y') + '.txt'
                    with open(filepath, 'a+') as filestreamer:
                        filestreamer.write(result + '\n')
                        filestreamer.close()

                return
            else:
                return
        return

if __name__ == '__main__':
    panel = MainWindow()
    panel = mainloop()
