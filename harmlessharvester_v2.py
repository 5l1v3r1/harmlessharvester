#!/usr/bin/env python3
import sys, os, time, getpass, threading, webbrowser, socket
from datetime import datetime, timedelta
from logging import getLogger, ERROR
import os, sys, time, hashlib
from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox
from ttkthemes import ThemedStyle

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

class Login(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title(string = "Login")
        self.resizable(0,0)
        #self.style = Style()
        #self.style.theme_use("clam")
        self.ttkStyle = ThemedStyle()
        self.ttkStyle.set_theme("arc")
        self.configure(background = 'white')
        icon = PhotoImage(file='icon.png')
        self.tk.call('wm', 'iconphoto', self._w, icon)
        self.eval('tk::PlaceWindow %s center' % self.winfo_pathname(self.winfo_id()))

        self.bind("<Escape>", self.exit) # Press ESC to quit app

        self.options = {
            'username' : StringVar(),
            'pwd' : StringVar(),
            'reg_username' : StringVar(),
            'reg_password' : StringVar(),
            'reg_check_password' : StringVar(),
        }

        photo = PhotoImage(file='images/login_img.png')
        #photo = photo.zoom(2)
        photo = photo.subsample(1)
        label = Label(self, image=photo, background = 'white')
        label.image = photo # keep a reference!
        label.grid(row = 0, column = 0, columnspan = 2)

        Label(self, text = 'Username', background = 'white', foreground = 'black', font='Helvetica 12 bold').grid(row = 1, column = 0)
        self.a = Entry(self, textvariable = self.options['username'], width = 30)
        self.a.grid(row = 2, column = 0, columnspan = 2)
        self.a.focus()

        Label(self, text = 'Password', background = 'white', foreground = 'black', font='Helvetica 12 bold').grid(row = 3, column = 0)
        Entry(self, textvariable = self.options['pwd'], show = '*', width = 30).grid(row = 4, column = 0, columnspan = 2)

        login_clk = Button(self, text = 'Login', command = self.login, width = 30).grid(row = 5, column = 0, columnspan = 2)
        register_clk = Button(self, text = 'Register', command = self.register, width = 30).grid(row = 6, column = 0, columnspan = 2)
        close = Button(self, text = 'Exit', command = self.destroy, width = 30).grid(row = 7, column = 0, columnspan = 2)
        self.bind("<Return>", self.login_event) # Press ESC to quit app

    def login_event(self, event):
        self.login() # Redirect to login on event (hotkey is bound to <Return>)

    def login(self):
        # Check username and password
        check_pwd = hashlib.sha256(self.options['pwd'].get().encode('utf-8')).hexdigest()

        for user in open('./users.txt').readlines():
            if self.options['username'].get() == user.split(':')[0].strip() and check_pwd == user.split(':')[1].strip():
                self.destroy()
                main = MainWindow()
                main.mainloop()
                return
            #else:
            #    print(user.split(':')[0])

        messagebox.showwarning('ERROR', 'Invalid username or password!')

    def exit(self, event):
        sys.exit(0)

    def register(self):
        self.reg = Toplevel()
        self.reg.title(string = 'Register')
        self.reg.configure(background = 'white')
        self.reg.resizable(0,0)

        reg_photo = PhotoImage(file='images/register.png')
        #photo = photo.zoom(2)
        reg_photo = reg_photo.subsample(2)
        label = Label(self.reg, image=reg_photo, background = 'white')
        label.image = reg_photo # keep a reference!
        label.grid(row = 0, column = 0, columnspan = 2)

        check = '' # Confirm password variable

        Label(self.reg, text = 'Username', background = 'white').grid(row = 1, column = 0)
        self.options['reg_username'] = Entry(self.reg, textvariable = self.options['reg_username'], width = 30)
        self.options['reg_username'].grid(row = 2, column = 0, columnspan = 2)
        self.options['reg_username'].focus()

        Label(self.reg, text = 'Password', background = 'white').grid(row = 3, column = 0)
        self.options['reg_password'] = Entry(self.reg, textvariable = self.options['reg_password'], width = 30, show = '*')
        self.options['reg_password'].grid(row = 4, column = 0, columnspan = 2)

        Label(self.reg, text = 'Confirm Password', background = 'white').grid(row = 5, column = 0)
        self.options['reg_check_password'] = Entry(self.reg, textvariable = self.options['reg_check_password'], width = 30, show = '*')
        self.options['reg_check_password'].grid(row = 6, column = 0, columnspan = 2)

        register_button = Button(self.reg, text = 'Register', command = self.register_user, width = 30)
        register_button.grid(row = 7, column = 0, columnspan = 2)
        self.reg.bind('<Return>', self.register_user_event)
        close_register = Button(self.reg, text = 'Cancel', command = self.destroy, width = 30).grid(row = 8, column = 0, columnspan = 2)


    def register_user_event(self, event):
        self.register_user()

    def register_user(self):

        # Check if passwords match
        if not self.options['reg_password'].get() == self.options['reg_check_password'].get():
            messagebox.showwarning('ERROR', 'Passwords do not match!')
            return
        else:
            pass

        # Check if every entry was filled
        if self.options['reg_username'].get() == '' or self.options['reg_password'].get() == '':
            messagebox.showwarning("ERROR", "Not all fields were filled!")
            return
        else:
            pass

        # check if username already exists
        try:
            for user in open('./users.txt').readlines():
                if user.split(':')[0] == self.options['reg_username'].get():
                    messagebox.showwarning('ERROR', 'Username already exists!')
                    return
                else:
                    pass
        except Exception:
            pass

        # Write data to local file
        with open('./users.txt', 'a+') as f:
            f.write('%s:%s\n' % (self.options['reg_username'].get(), hashlib.sha256(self.options['reg_password'].get().encode('utf-8')).hexdigest()))
            f.close()

        messagebox.showinfo('INFO', 'User registered!')

        self.reg.destroy()

class MainWindow(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title(string = 'Harmless Harvester - HTTP/HTTPS traffic dump')
        self.resizable(0,0)
        #self.style = Style()
        #self.style.theme_use("clam")
        self.ttkStyle = ThemedStyle()
        self.ttkStyle.set_theme("arc")
        self.configure(background = 'black')
        icon = PhotoImage(file='images/icon.png')
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

        photo = PhotoImage(file='images/icon.png')
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
        messagebox.showinfo('INFO', 'File save to %s' % filepath)

    def live_logging(self):
        global log
        if log == True:
            log = False
            messagebox.showinfo('INFO', 'Logging disabled')
        else:
            log = True
            messagebox.showinfo('INFO', 'Logging enabled')

    def ssl_sniff(self):
        global ssl
        if ssl == True:
            ssl == False
            messagebox.showinfo('INFO', 'SSL Sniffing disabled')
        else:
            ssl == True
            messagebox.showinfo('INFO', 'SSL Sniffing enabled')

    def password_detection(self):
        global pwd
        if pwd == True:
            pwd = False
            messagebox.showinfo('INFO', 'Password Detection disabled')
        else:
            pwd = True
            messagebox.showinfo('INFO', 'Password Detection enabled')


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
        messagebox.showinfo("INFO", "Comming Soon! Please like and watch this github repo - Thank You")

    def dump(self):
        sniff(iface=self.options['interface'].get(), prn=self.check_pkt, store=0)

    def start_thread(self):
        # Start time thread

        if self.options['interface'].get() == '':
            messagebox.showwarning("ERROR", "Please enter a interface to sniff with")
            return
        else:
            messagebox.showinfo("INFO", "Sniffing started on interface: %s" % self.options['interface'].get())

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

            result = '[' + time.strftime('%d-%m-%Y') + ' ' + time.strftime('%X') + "] %s" % src + "%s" % (dst).ljust(20) + "| Host: %s" % (host).ljust(50)

            self.options['result'].insert(END, result)
            self.options['result'].yview(END)



        if pwd == True:
            if b'password' in data:
                print('Password detected!\n--------------------\n%s' % data)

        # If data contains a link
        if b'Referer:' in data:
            link = data.split(b'\r') # Find hostname
            target = link[1].split(b' ') # Get "just" the hostname
            if target[1] not in HARVESTER:
                HARVESTER.append(target[1])

                src = str(pkt[IP].src).strip() # Get source

                # Resolve hostname into IP address
                dst = ' >> ' + str(pkt[IP].dst).strip() # Get destination


                # Print result, depending on situation
                result = '[' + time.strftime('%d-%-m-%Y') + ' ' + time.strftime('%X') + "] %s" % src + "%s" % (dst).ljust(20) + "| Host: %s" % (target[1]).ljust(50)

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

logon = Login()
logon.mainloop()
