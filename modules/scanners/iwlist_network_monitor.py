#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 1.0

##################################
#        Scanners Module         #
#  Network monitor using iwlist  #
##################################

import subprocess
import sys
import time
import re
import json
import os
import signal
import modules.colors as colors
import queue as Queue
import multiprocessing
from datetime import timedelta

captured_aps = []
table_of_manufacturers = {}


def getTimeDate():
    return time.strftime("%X") + " " + time.strftime("%x")

def getTimeDate2():
    return time.strftime("%x").replace("/", "")+"_"+time.strftime("%X")


def scan(*arg):

    interface = arg[0]
    ssids= arg[1]
    table = ['Date', 'AP Name', 'CH', 'BSSID', 'Signal', 'Quality',
             'Frequency', 'Encryption', 'Cipher', 'Authentication', 'TSF']
    print(colors. get_color("BOLD") + '{:^22s}|{:^24s}|{:^9s}|{:^19s}|{:^8s}|{:^9s}|{:^11s}|{:^18s}|{:^8s}|{:^16s}|{:^16s}'.format(
        table[0], table[1], table[2], table[3], table[4], table[5], table[6], table[7], table[8], table[9], table[10]) + colors.get_color("ENDC"), flush=True)
    while True:
        ap_list = get_results(interface)
        try:
            for line in ap_list:
                # filter to check if APs already exists
                if filter_aps(line):
                    print('{:^22s} {:<23s}  {:^9s} {:^19s} {:^8s} {:^9s} {:^10s} {:^18s} {:^8s} {:^16s}   {:<18s}'.format(getTimeDate(
                                ), line['essid'], line['channel'], line['mac'], line['signal'], line['quality'], line['frequency'], line['key type'], line['group cipher'], line['authentication suites'], line['tsf']),flush=True)
                    captured_aps.append(line)
            time.sleep(1)
        except Exception as err:
            print(err,"ERROR")
            pass

def filter_aps(*arg):
    access_point = arg[0]
    filtered_ssid = ""

    for ap in captured_aps:
        try:
            if ap['essid'] == access_point['essid'] and ap['mac'] == access_point['mac'] and ap['channel'] == access_point['channel'] and ap['key type'] == access_point['key type'] and ap['group cipher'] == access_point['group cipher'] and (abs(int(access_point['signal'])) <= abs(int(ap['signal']))+20 and abs(int(access_point['signal'])) >= abs(int(ap['signal']))-20):
                return False
        except Exception as e:
            print(e)
            pass
    return True

def get_results(interface):
    list_of_results = []
    try:
        # call the process to get the output to parse
        proc = subprocess.check_output(
            "sudo iwlist "+interface+" scan", shell=True).decode(encoding="utf-8", errors="strict")
        # break the output making an array containing the info of each Access Point
        list_of_results = re.split(r'\bCell \d{2}\b - ', proc)[1:]
    except subprocess.CalledProcessError:
        print("Get result failed..")
    return parse(list_of_results)

def parse(networks):
    parsed_list = []

    for network in networks:
        try:
            ap = {}
            network = network.strip()
            essid = ""
            address = ""
            quality = ""
            signal = ""
            channel = ""
            encryption_key = ""
            key_type = ""
            group_cipher = ""
            pairwise_cipher = ""
            authentication_suites = ""
            tsf = ""
            frequency = ""

            # Get Frequency
            match = re.search('Frequency:(\S+)', network)
            if match:
                frequency = match.group(1)
                ap.update({"frequency": frequency})

            # Get the TSF
            match = re.search('Extra:tsf=(\S+)', network)
            if match:
                tsf = match.group(1)
                i = int(tsf, 16)
                tsf = str(timedelta(microseconds=i))[:-4]
                ap.update({"tsf": tsf})

            # Get the name of the AP
            match = re.search('ESSID:"(([ ]*(\S+)*)*)"', network)
            if match:
                essid = match.group(1)
                ap.update({"essid": essid})

            # Get the BSSID of the AP
            match = re.search('Address: (\S+)', network)
            if match:
                address = match.group(1)
                ap.update({"mac": address})

            # Get the Channel of the AP
            match = re.search('Channel:(\S+)', network)
            if match:
                channel = match.group(1)
                ap.update({"channel": channel})

            # Find the brand of the AP

            # Get the quality of the signal and the signal level
            match = re.search(
                'Quality=(\d+/\d+)  Signal level=(-\d+) dBm', network)
            if match:
                quality = match.group(1)
                a = quality[0:2]
                b = quality[3:5]
                quality_calc = format((float(a)/float(b)), '.2f')
                signal = match.group(2)
                ap.update({"quality": quality})
                ap.update({"quality_calc": quality_calc})
                ap.update({"signal": signal})

            # Check if there is an Encryption key on the AP
            match = re.search('Encryption key:(\S+)', network)
            if match:
                encryption_key = match.group(1)
                ap.update({"encryption": encryption_key})

            # Find the encryption type (WEP, WPA, WPA2 or Open)
            match = re.search(r'(?<=802.11i/)[a-zA-Z0-9_ ]*', network)
            if match and match != "Unknown" and match != "IEEE 802":
                key_type = match.group(0)
                ap.update({"key type": key_type})
            elif ap['encryption'] == 'on':
                key_type = "WEP"
                ap.update({"key type": key_type})
            else:
                key_type = "Open"
                ap.update({"key type": key_type})

            # Get the Cipher being used
            match = re.search(r'Group Cipher : ([a-zA-Z0-9_ ]*)', network)
            if match:
                group_cipher = match.group(1)
                ap.update({"group cipher": group_cipher})
            elif ap['encryption'] == 'on':
                group_cipher = "WEP"
                ap.update({"group cipher": group_cipher})
            else:
                group_cipher = ""
                ap.update({"group cipher": group_cipher})

            # Get the Pairwise Cipher being used
            match = re.search(
                'Pairwise Ciphers ([(\d+)]*) : ([a-zA-Z0-9_ ]*)', network)
            if match:
                pairwise_cipher = match.group(2)
                ap.update({"pairwise cipher": pairwise_cipher})
            elif ap['encryption'] == 'on':
                pairwise_cipher = "WEP"
                ap.update({"pairwise cipher": pairwise_cipher})
            else:
                pairwise_cipher = ""
                ap.update({"pairwise cipher": pairwise_cipher})

            # Get the Authentication Suites
            match = re.search(
                'Authentication Suites ([(\d+)]*) : ([a-zA-Z0-9_ ]*)', network)
            if match:
                authentication_suites = match.group(2)
                ap.update({"authentication suites": authentication_suites})
            elif ap['encryption'] == 'on':
                authentication_suites = ""
                ap.update({"authentication suites": authentication_suites})
            else:
                authentication_suites = ""
                ap.update({"authentication suites": authentication_suites})

            parsed_list.append(ap)
        except:
            pass

    return parsed_list
