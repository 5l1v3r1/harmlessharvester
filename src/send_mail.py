#!/usr/bin/python
# Version 1.0
import os, smtplib, getpass, sys, fileinput, time, threading
from src.read_config import *

def send_mail(result):
    body = '''
    Dear %s,

    A blacklisted ip address was visited:

    %s

    Kind regards,

    Administrator

    --------------------------------------------------------------------

    Please note:
    This message was send with a beta python script.
    If you received invalid information, please contact us.
    ''' % (getpass.getuser(), result)

    try:
        server = smtplib.SMTP(CONFIG.EMAIL_SMTP,CONFIG.EMAIL_PORT)
        server.ehlo(); server.starttls()
        server.login(CONFIG.EMAIL_ADDRESS,CONFIG.EMAIL_PASSWORD)
        for i in range(1, 1+1): # Send one
           subject = '[WARNING] HarmlessHarvester detected blacklisted host'
           msg = 'From: ' + getpass.getuser() + '\nSubject: ' + subject + '\n' + body
           server.sendmail(getpass.getuser(),CONFIG.EMAIL_ADDRESS,msg) # Send message
           server.quit()

           #print('\nMessage was successfully sent to: ' + CONFIG.EMAIL_ADDRESS)    # Debug
           #print('Now sleeping for %s seconds' % CONFIG.EMAIL_COOLDOWN)            # Debug
    except KeyboardInterrupt:
       print('[ - ] Canceled')
       sys.exit(1)
    except smtplib.SMTPAuthenticationError:
       print('\n[ ! ] Failed to login: The username or password you entered is incorrect.')
       sys.exit()
