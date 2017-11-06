#/usr/bin/python3
import os, sys, time, datetime

class CONFIG():
    def __init__(self):
        self.WWWONLY = ''
    def __init__(self):
        self.LOGGING = ''
    def __init__(self):
        self.LOG_DIR = ''
    def __init__(self):
        self.LOGFILE = ''
    def __init__(self):
        self.SHOW_IP = ''
    def __init__(self):
        self.DUPLICATE_COOLDOWN = ''
    def __init__(self):
        self.EMAIL_WARNING = ''
    def __init__(self):
        self.EMAIL_ADDRESS = ''
    def __init__(self):
        self.EMAIL_PASSWORD = ''
    def __init__(self):
        self.EMAIL_SMTP = ''
    def __init__(self):
        self.EMAIL_PORT = ''
    def __init__(self):
        self.EMAIL_COOLDOWN = ''
    def __init__(self):
        self.PASSWD_IS_ENCRYPTED = ''
    def __init__(self):
        self.BLACKLIST = ''
    def __init__(self):
        self.COLOUR_BLACKLIST = ''
    def __init__(self):
        self.COLOUR_LOCAL = ''
    def __init__(self):
        self.AUTO_RESTART = ''

settings_path = sys.argv[0].replace('harmlessharvester.py', 'settings')     # Fix to find 'settings' file

if not os.path.isfile(settings_path):
    print('HarmlessHarvester is not installed - Where is the settings file?'); sys.exit(1)
else:
    config_file = open(settings_path).readlines(); print('\033[1;95m[CONFIG]\033[0m')

conf_error = '[ERROR] Invalid syntax detected in config'

def time_full():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S')
def time_time():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
def time_date():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%d-%m-%Y')

# Reading config_file
def config_reader():
    for line in config_file:
        if not line.startswith('#'):
            # wwwOnly
            if line.startswith('WWWONLY'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.WWWONLY = False
                elif line[1] == 'on'.lower():
                    CONFIG.WWWONLY = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # Logging
            elif line.startswith('LOGGING'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.LOGGING = False
                elif line[1] == 'on'.lower():
                    CONFIG.LOGGING = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # Check log dir
            elif line.startswith('LOG_DIR'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                if os.path.isdir(line[1]):
                    CONFIG.LOGFILE = line[1] + 'harmlessharvester - ' + time_date() + '.log'
                    CONFIG.LOG_DIR = line[1]
                    print('\t\033[94m[LOGFILE]\033[0m ' + CONFIG.LOGFILE)
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # SHOW_IP
            elif line.startswith('SHOW_IP'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.SHOW_IP = False
                elif line[1] == 'on'.lower():
                    CONFIG.SHOW_IP = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # DUPLICATE_COOLDOWN
            elif line.startswith('DUPLICATE_COOLDOWN'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                minutes = int(line[1]) / 60
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1] + ' seconds' + ' (%i minutes)' % minutes)
                if line[1]:
                    CONFIG.DUPLICATE_COOLDOWN = line[1]
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_WARNING
            elif line.startswith('EMAIL_WARNING'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.EMAIL_WARNING = False
                elif line[1] == 'on'.lower():
                    CONFIG.EMAIL_WARNING = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_ADDRESS
            elif line.startswith('EMAIL_ADDRESS'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if '@' in line[1]:
                    CONFIG.EMAIL_ADDRESS = line[1]
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_PASSWORD
            elif line.startswith('EMAIL_PASSWORD'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                #print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])     # Prefer not to show the password everytime you start
                if line[1]:
                    CONFIG.EMAIL_PASSWORD = line[1]
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_SMTP
            elif line.startswith('EMAIL_SMTP'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                if line[1]:
                    CONFIG.EMAIL_SMTP = line[1]
                    print('\t\033[94m[' + line[0] + ']\033[0m ' + CONFIG.EMAIL_SMTP)
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_PORT
            elif line.startswith('EMAIL_PORT'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                if line[1]:
                    CONFIG.EMAIL_PORT = line[1]
                    print('\t\033[94m[' + line[0] + ']\033[0m ' + CONFIG.EMAIL_PORT)
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # EMAIL_COOLDOWN
            elif line.startswith('EMAIL_COOLDOWN'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                minutes = int(line[1]) / 60
                if line[1]:
                    CONFIG.EMAIL_COOLDOWN = line[1]
                    print('\t\033[94m[' + line[0] + ']\033[0m ' + CONFIG.EMAIL_COOLDOWN + " seconds (%i minutes)" % minutes)
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # PASSWD_IS_ENCRYPTED
            elif line.startswith('PASSWD_IS_ENCRYPTED'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.PASSWD_IS_ENCRYPTED = False
                elif line[1] == 'on'.lower():
                    CONFIG.PASSWD_IS_ENCRYPTED = True
                    from src.encrypt import *       # Import encrypter
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # BLACKLIST
            elif line.startswith('BLACKLIST'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                if os.path.isfile(line[1]):
                    CONFIG.BLACKLIST = line[1]
                    print('\t\033[94m[BLACKLIST]\033[0m ' + CONFIG.BLACKLIST)
                elif os.path.isfile(sys.argv[0].replace('harmlessharvester.py', line[1])):
                    CONFIG.BLACKLIST = sys.argv[0].replace('harmlessharvester.py', line[1])
                    print('\t\033[94m[BLACKLIST]\033[0m ' + CONFIG.BLACKLIST)
                else:
                    print(conf_error + ' >> %s=>%s<' % (line[0], line[1])); sys.exit(1)

            # COLOUR_BLACKLIST
            elif line.startswith('COLOUR_BLACKLIST'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\33[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.COLOUR_BLACKLIST = False
                elif line[1] == 'on'.lower():
                    CONFIG.COLOUR_BLACKLIST = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

            # COLOUR_LOCAL
            elif line.startswith('COLOUR_LOCAL'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\033[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1]:
                    CONFIG.COLOUR_LOCAL = line[1]

            # AUTO_RESTART
            elif line.startswith('AUTO_RESTART'):
                line = line.rstrip(); line = line.replace('"', "")
                line = line.split('=')
                print('\t\33[94m[' + line[0] + ']\033[0m ' + line[1])
                if line[1] == 'off'.lower():
                    CONFIG.AUTO_RESTART = False
                elif line[1] == 'on'.lower():
                    CONFIG.AUTO_RESTART = True
                else:
                    print(conf_error + ' >> %s = >%s<' % (line[0], line[1])); sys.exit(1)

config_reader()
