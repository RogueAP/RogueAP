#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Rogue Access Point Detector
# version: 1.0
# author: Team Rogue_AP

##################################
#        Rogue AP Detector       #
#           Main Module          #
##################################

import os, string, threading, sys, time, queue as Queue, multiprocessing, subprocess
import modules.scanners.iwlist_network_monitor as iwlist_monitor
import modules.manage_interfaces as manage_interfaces
import modules.colors as colors
import json

def print_info(info, type=0):
    if (type == 0):
        m = colors.get_color("OKBLUE")
    elif (type == 1):
        m = colors.get_color("OKGREEN")
    elif (type == 2):
        m = colors.get_color("WARNING")
    m += "[*] " + colors.get_color("ENDC") + colors.get_color("BOLD") + info + colors.get_color("ENDC")
    print(m)

def intro():
	print(colors.get_color("BOLD") +
	 "                               _    ____    ____       _            _     \n"+
	 " _ __ ___   __ _ _   _  ___   / \  |  _ \  |  _ \  ___| |_ ___  ___| |_ \n" +
	 "| '__/ _ \ / _` | | | |/ _ \ / _ \ | |_) | | | | |/ _ \ __/ _ \/ __| __| \n" +
	 "| | | (_) | (_| | |_| |  __// ___ \|  __/  | |_| |  __/ ||  __/ (__| |_ \n"+
	 "|_|  \___/ \__, |\__,_|\___/_/   \_\_|     |____/ \___|\__\___|\___|\__| \n "+
	 "          |___/                                                   v1.0\n"+
     "\t\t\t\tby Team Rogue_AP\n"+ colors.get_color("ENDC"))

def usage():
	intro()
	print_info("Usage: ./rogue_detector.py [option]")
	print("\nOptions:  -i interface\t\t -> the interface to monitor the network")
	print("\t  -s scan_type\t\t -> name of scanning type (iwlist, scapy)")

	print(colors.get_color("BOLD")+"\nExample:sudo python3 ./rogue_detector.py -i iface -s iwlist"+colors.get_color("ENDC"))

def parse_args(ssids):
	intro()
	scanner_type = ""
	scan = False

	if (len(sys.argv) < 4):
		usage()
		return

	# setting up args
	for cmd in sys.argv:
		if (cmd == "-i"):
			global interface
			interface = sys.argv[sys.argv.index(cmd)+1]
			pre_check(interface)
			
		if (cmd == "-s"):
			scan = True
			scanner_type = sys.argv[sys.argv.index(cmd)+1]

	if (scan):
		if (scanner_type == "iwlist"):
			try:
				iwlist_monitor.scan(interface, ssids)
			except Exception as e:
				print("Exception:114 %s" %e)
				return

def pre_check(iface):
	try:
		if(iface):
			check_interface(iface)
	except:
		sys.exit(0)

def check_interface(iface):
	try:
		outputz = subprocess.check_output("iwlist " + iface + " scan", stderr=subprocess.STDOUT, shell=True)
	except Exception as e:
		print(colors.get_color("ORANGE") + "Please check your interface." + colors.get_color("ENDC"))
		print(colors.get_color("GRAY") + "Exception: %s" % e + colors.get_color("ENDC") )
		sys.exit(1)

def check_root():
	if os.geteuid() != 0:
		print(colors.get_color("FAIL") + "[!] Requires root" + colors.get_color("ENDC"))
		sys.exit(0)

def main():
	check_root()
	try:
		with open('ssids.json') as f:
			ssids = json.load(f)
			print(colors.get_color("ORANGE") + str(ssids) + colors.get_color("ENDC"))
	except:
		print(colors.get_color("FAIL") + "[x] File SSID.json Not Found" + colors.get_color("ENDC"))
		sys.exit(0)
	parse_args(ssids)
	
	
	
if __name__ == '__main__':
	main()