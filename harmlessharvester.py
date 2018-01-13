#!/usr/bin/python3
# Version 0.9.x
import sys, os, socket, time, getpass, threading, argparse
from datetime import datetime, timedelta
from logging import getLogger, ERROR
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

def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser(prog='HarmlessHarvester')

    parser.add_argument("-i",
                        "--interface",
                        help="Choose monitor mode interface. \
                                Example: -i eth0")
    parser.add_argument("-l", "--log", help="Log traffic to file")

    return parser.parse_args()

args = parse_args()

if args.interface == None:
    print('[ERROR] No interface given'); sys.exit(1)
else:
    interface = args.interface

from src.read_config import *

if CONFIG.EMAIL_WARNING == True:
    from src.send_mail import *         # Import mail script


#if (len(sys.argv) < 2):
#    print('[ERROR] No interface given'); sys.exit(1)

# Temp solution for multiple interfaces, only works with Konsole
#elif (len(sys.argv) > 2):
#    for i in sys.argv:
#        if not i.endswith('.py'):
#            try:
#                os.system("konsole --geometry=90x25 --new-tab -e 'bash -c \"sudo python %s %s ; exec bash\"'" % (sys.argv[0], i))
#            except Exception as e:
#                print('[ERROR] Only supports Konsole! Is it installed? >> %s' % e); sys.exit(1)
#    sys.exit(1)
#else:
#    interface = sys.argv[1]

# Save collected Data for x seconds
HARVESTER = []

def CLEAR_HARVESTER():
    global HARVESTER
    while 1:
        HARVESTER = []
        #print('Harvester cleared')  # Debug
        time.sleep(int(CONFIG.DUPLICATE_COOLDOWN))

# Start Background thread for cooldowns
harvester_timer = threading.Thread(target=CLEAR_HARVESTER)
harvester_timer.daemon = True; harvester_timer.start()

#print(CONFIG.LOG_DIR)    # Debug
#send_mail('Debug!')     # Debug

def read_connection(pkt):
    # Read data on TCP port 80 only
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            return True
        else:
            return False
    else:
        return False

def check_pkt(pkt):
    global HARVESTER

    # If TCP 80 > Pass, else > Return
    if read_connection(pkt):
        pass
    else:
        return
    data = pkt[Raw].load

    # Create new LOGFILE if date changed
    if not CONFIG.LOGFILE.endswith(time_date() + '.csv'):
        CONFIG.LOGFILE = CONFIG.LOG_DIR + 'harmlessharvester - ' + time_date() + '.csv'

    # If data contains a link
    if 'Referer:' in data:
        link = data.split('\r') # Find hostname
        target = link[1].split(" ") # Get "just" the hostname
        if target[1] not in HARVESTER:
            HARVESTER.append(target[1])

            src = str(pkt[IP].src).strip() # Get source

            # Resolve hostname into IP address
            try:
                if CONFIG.SHOW_IP == True:
                    dst = ' >> ' + str(pkt[IP].dst).strip() # Get destination
                else:
                    dst = ''
            except socket.gaierror:
                dst = 'Unable to resolve hostname'
            except Exception as e:
                dst = e


            # Print result, depending on situation
            result = '[' + time_date() + ' ' + time_time() + "] \033[1;92m%s" % src + "%s" % (dst).ljust(20) + "| Host: %s\033[0m" % (target[1]).ljust(50)
            result_colour = '[' + time_date() + ' ' + time_time() + "] \033[1;91m%s" % src + "%s" % (dst).ljust(20) + "| Host: %s\033[0m" % (target[1]).ljust(50)
            #result_mail = '[' + time_date() + ' ' + time_time() + "] %s" % src + "%s" % (dst).ljust(20) + "| Host: %s" % (target[1]).ljust(50)
            result_mail = time_date() + ' ' + time_time() + ",%s," % src + "%s," % (dst) + "Host: %s" % (target[1])

            # The old output: Date > Time > Host > Dest > src
            # New output: Date > Time > Src > Dest > Host
            #result = '[' + time_date() + ' ' + time_time() + "] \033[1;92mHost: %s" % (target[1]).ljust(50) + "%s" % (dst).ljust(20) + "%s\033[0m" % src

            # If colour_blacklist is ON, do this
            if CONFIG.COLOUR_BLACKLIST == True:
                for line in open(CONFIG.BLACKLIST, 'r').readlines():
                    if not line.startswith('#'):
                        if str(pkt[IP].src).strip() in line:
                            print(result_colour)
                        elif target[1] in line:
                            print(result_colour)
                        elif CONFIG.COLOUR_LOCAL:
                            try:
                                if str(pkt[IP].src).strip().startswith(CONFIG.COLOUR_LOCAL):
                                    print(result_colour)
                                else:
                                    print(result)
                            except Exception as e:
                                print('[COLOUR_LOCAL] Error - ' + e)
            else:
                if CONFIG.COLOUR_LOCAL:
                    try:
                        if str(pkt[IP].src).strip().startswith(CONFIG.COLOUR_LOCAL):
                            print(result_colour)
                        else:
                            print(result)
                    except Exception as e:
                        print('[COLOUR_LOCAL] Error - ' + e)

            # If EMAIL_WARNING is ON, do this too
            if CONFIG.EMAIL_WARNING == True:
                for line in open(CONFIG.BLACKLIST, 'r').readlines():
                    if not line.startswith('#'):
                        # EMAIL_WARNING handler
                        if str(pkt[IP].src).strip() in line:
                            try:
                                send_mail(result_mail)
                            except Exception as e:
                                print('[ERROR]' + e)
                        elif target[1] in line:
                            try:
                                send_mail(result_mail)
                            except Exception as e:
                                print('[ERROR]' + e)

            if CONFIG.LOGGING == True:
                with open(CONFIG.LOGFILE, 'a+') as f:
                    f.write(result_mail + '\n')
                    f.close()
            return
        else:
            return
    return

print('\n\033[1;92m[*]\033[0m \033[1;95mDumping data from interface %s...\033[0m\n') % interface
print("\033[1;95mStarted: " + time.strftime("%c") + "\033[0m")

try:
    sniff(iface=interface, prn=check_pkt, store=0)
except Exception as e:
    print('\033[1;91m[!] Failed to Initialize - %s\033[0m' % e)
    if CONFIG.LOGGING == True:
        with open(CONFIG.LOGFILE, 'a+') as f:
            f.write('[!] Failed to Initialize - ' + e)
            f.write('Ended: ' + time.strftime("%c"))
            f.close()
    # Try to restart the script
    if CONFIG.AUTO_RESTART == True:
        os.system("sudo python " + sys.argv[0] + " " + sys.argv[1] + " &"); sys.exit(1)
    sys.exit(1)
print('\n\033[1;91m[*] Canceled\033[0m')
print('\033[1;95mEnded: ' + time.strftime("%c")) + '\033[0m'
if CONFIG.LOGGING == True:
    with open(CONFIG.LOGFILE, 'a+') as f:
        f.write('Ended: ' + time.strftime("%c") + '\n')
        f.close()
