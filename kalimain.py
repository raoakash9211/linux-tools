## kalitools.py
import os
import sys
from time import sleep as timeout
from core.kalicore import *

def main():
	banner()
	print ("   [01] Information Gathering")
	print ("   [02] Vulnerability Analysis")
	print ("   [03] Wireless Attacks")
	print ("   [04] Web Applications")
	print ("   [05] Exploitation Tools")
	print ("   [06] Stress Testing")
	print ("   [07] Forensic Tools")
	print ("   [08] Sniffing & Spoofing")
	print ("   [09] Password Attacks")
	print ("   [10] Maintaining Access")
	print ("   [11] Reverse Engineering")
	print ("   [12] Reporintg Tools")
	print ("   [13] Hardware Hacking")
	print ("   [00] Exit the Kali toolkit\n")
	kali = input("kali > ")
	
	if kali == "1" or kali == "01":
		print ("\n    [01] acccheck")
		print ("    [02] ace-voip")
		print ("    [03] Amap")
		print ("    [04] APT2")
		print ("    [05] arp-scan")
		print ("    [06] Automater")
		print ("    [07] bing-ip2hosts")
		print ("    [08] braa")
		print ("    [09] CaseFile")
		print ("    [10] CDPSnarf")
		print ("    [11] cisco-torch")
		print ("    [12] Cookie-Cadger")
		print ("    [13] copy-router-config")
		print ("    [14] DMitry")
		print ("    [15] dnmap")
		print ("    [16] dnsenum")
		print ("    [17] dnsmap")
		print ("    [18] DNSRecon")
		print ("    [19] dnstracer")
		print ("    [20] dnswalk")
		print ("    [21] DotDotPwn")
		print ("    [22] enum4linux")
		print ("    [23] enumIAX")
		print ("    [24] EyeWitness")
		print ("    [25] Faraday")
		print ("    [26] Fierce")
		print ("    [27] Firewalk")
		print ("    [28] fragroute")
		print ("    [29] fragrouter")
		print ("    [30] Ghost Phisher")
		print ("    [31] GoLismero")
		print ("    [32] goofile")
		print ("    [33] hping3")
		print ("    [34] ident-user-enum")
		print ("    [35] InSpy")
		print ("    [36] InTrace")
		print ("    [37] iSMTP")
		print ("    [38] Ibd")
		print ("    [39] Maltego Teeth")
		print ("    [40] masscan")
		print ("    [41] Metagoofil")
		print ("    [42] Miranda")
		print ("    [43] nbtscan-unixwiz")
		print ("    [44] Nikto")
		print ("    [45] Nmap")
		print ("    [46] ntop")
		print ("    [47] OSRFramework")
		print ("    [48] p0f")
		print ("    [49] Parsero")
		print ("    [50] Recon-ng")
		print ("    [51] SET")
		print ("    [52] SMBMap")
		print ("    [53] smtp-user-enum")
		print ("    [54] snmp-check")
		print ("    [55] SPARTA")
		print ("    [56] sslcaudit")
		print ("    [57] SSLsplit")
		print ("    [58] sslstrip")
		print ("    [59] SSLyze")
		print ("    [60] Sublist3r")
		print ("    [61] THC-IPV6")
		print ("    [62] theHarvester")
		print ("    [63] TLSSLed")
		print ("    [64] twofi")
		print ("    [65] Unicornscan")
		print ("    [66] URLCrazy")
		print ("    [67] Wireshark")
		print ("    [68] WOL-E")
		print ("    [69] Xplico\n")
		print ("    [99] Back to main menu\n")
		infogathering = input("kali > ")
		
		if infogathering == "01" or infogathering == "1":
			acccheck()
		elif infogathering == "02" or infogathering == "2":
			ace-voip()
		elif infogathering == "03" or infogathering == "3":
			amap()
		elif infogathering == "04" or infogathering == "4":
			apt2()
		elif infogathering == "05" or infogathering == "5":
			arp_scan()
		elif infogathering == "06" or infogathering == "6":
			automater()
		elif infogathering == "07" or infogathering == "7":
			bing_ip2hosts()
		elif infogathering == "08" or infogathering == "8":
			braa()
		elif infogathering == "09" or infogathering == "9":
			casefile()
		elif infogathering == "10":
			cdpsnarf()
		elif infogathering == "11":
			cisco_torch()
		elif infogathering == "12":
			cookie_cadger()
		elif infogathering == "13":
			copy_router_config()
		elif infogathering == "14":
			dmitry()
		elif infogathering == "15":
			dnmap()
		elif infogathering == "16":
			dnsenum()
		elif infogathering == "17":
			dnsmap()
		elif infogathering == "18":
			dnsrecon()
		elif infogathering == "19":
			dnstracer()
		elif infogathering == "20":
			dnswalk()
		elif infogathering == "21":
			dotdotpwn()
		elif infogathering == "22":
			enum4linux()
		elif infogathering == "23":
			enumiax()
		elif infogathering == "24":
			eyewitness()
		elif infogathering == "25":
			faraday()
		elif infogathering == "26":
			fierce()
		elif infogathering == "27":
			firewalk()
		elif infogathering == "28":
			fragroute()
		elif infogathering == "29":
			fragrouter()
		elif infogathering == "30":
			ghost_phisher()
		elif infogathering == "31":
			golismero()
		elif infogathering == "32":
			goofile()
		elif infogathering == "33":
			hping3()
		elif infogathering == "34":
			ident_user_enum()
		elif infogathering == "35":
			inspy()
		elif infogathering == "36":
			intrace()
		elif infogathering == "37":
			ismtp()
		elif infogathering == "38":
			ibd()
		elif infogathering == "39":
			maltego_teeth()
		elif infogathering == "40":
			masscan()
		elif infogathering == "41":
			metagoofil()
		elif infogathering == "42":
			miranda()
		elif infogathering == "43":
			nbtscan_unixwiz()
		elif infogathering == "44":
			Nikto()
		elif infogathering == "45":
			nmap()
		elif infogathering == "46":
			ntop()
		elif infogathering == "47":
			OSRFramework()
		elif infogathering == "48":
			p0f()
		elif infogathering == "49":
			Parsero()
		elif infogathering == "50":
			recon_ng()
		elif infogathering == "51":
			set()
		elif infogathering == "52":
			smbmap()
		elif infogathering == "53":
			smtp_user_enum()
		elif infogathering == "54":
			snmp_check()
		elif infogathering == "55":
			sparta()
		elif infogathering == "56":
			sslcaudit()
		elif infogathering == "57":
			sslsplit()
		elif infogathering == "58":
			sslstrip()
		elif infogathering == "59":
			sslyze()
		elif infogathering == "60":
			sublist3r()
		elif infogathering == "61":
			thc_ipv6()
		elif infogathering == "62":
			theharvester()
		elif infogathering == "63":
			tlssled()
		elif infogathering == "64":
			twofi()
		elif infogathering == "65":
			unicornscan()
		elif infogathering == "66":
			urlcrazy()
		elif infogathering == "67":
			wireshark()
		elif infogathering == "68":
			wol_e()
		elif infogathering == "69":
			xplico()
		
		elif infogathering == "00" or infogathering == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "2" or kali == "02":
		print ("\n    [01] BBQSQL")
		print ("    [02] BED")
		print ("    [03] cisco-auditing-tool")
		print ("    [04] cisco-global-exploiter")
		print ("    [05] cisco-ocs")
		print ("    [06] cisco-torch")
		print ("    [07] copy-router-config")
		print ("    [08] DBPwAudit")
		print ("    [09] Doona")
		print ("    [10] DotDotPwn")
		print ("    [11] HexorBase")
		print ("    [12] Inguma")
		print ("    [13] jSQL Injection")
		print ("    [14] Lynis")
		print ("    [15] Nmap")
		print ("    [16] ohrwurm")
		print ("    [17] openvas")
		print ("    [18] Oscanner")
		print ("    [19] Powerfuzzer")
		print ("    [20] sfuzz")
		print ("    [21] SidGuesser")
		print ("    [22] SIPArmyKnife")
		print ("    [23] sqlmap")
		print ("    [24] sqlninja")
		print ("    [25] sqlsus")
		print ("    [26] THC-IPV6")
		print ("    [27] tnscmd10g")
		print ("    [28] unix-privese-check")
		print ("    [29] Yersinia")
		print ("    [00] Back to main menu\n")
		vulnanalysis = input("kali > ")
		
		if vulnanalysis == "01" or vulnanalysis == "1":
			bbqsql()
		elif vulnanalysis == "02" or vulnanalysis == "2":
			bed()
		elif vulnanalysis == "03" or vulnanalysis == "3":
			cisco_auditing_tool()
		elif vulnanalysis == "04" or vulnanalysis == "4":
			cisco_global_exploiter()
		elif vulnanalysis == "05" or vulnanalysis == "5":
			cisco_ocs()
		elif vulnanalysis == "06" or vulnanalysis == "6":
			cisco_torch()
		elif vulnanalysis == "07" or vulnanalysis == "7":
			copy_router_config()
		elif vulnanalysis == "08" or vulnanalysis == "8":
			dbpwaudit()
		elif vulnanalysis == "09" or vulnanalysis == "9":
			doona()
		elif vulnanalysis == "10":
			dotdotpwn()
		elif vulnanalysis == "11":
			hexorbase()
		elif vulnanalysis == "12":
			inguma()
		elif vulnanalysis == "13":
			jsql_injection()
		elif vulnanalysis == "14":
			lynis()
		elif vulnanalysis == "15":
			nmap()
		elif vulnanalysis == "16":
			ohrwurm()
		elif vulnanalysis == "17":
			openvas()
		elif vulnanalysis == "18":
			oscanner()
		elif vulnanalysis == "19":
			powerfuzzer()
		elif vulnanalysis == "20":
			sfuzz()
		elif vulnanalysis == "21":
			sidguesser()
		elif vulnanalysis == "22":
			siparmyknife()
		elif vulnanalysis == "23":
			sqlmap()
		elif vulnanalysis == "24":
			sqlninja()
		elif vulnanalysis == "25":
			sqlsus()
		elif vulnanalysis == "26":
			thc_ipv6()
		elif vulnanalysis == "27":
			tnscmd10g()
		elif vulnanalysis == "28":
			unix_privesc_check()
		elif vulnanalysis == "29":
			yersinia()
		elif vulnanalysis == "00" or vulnanalysis == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "3" or kali == "03":
		print ("\n    [01] Airbase-ng")
		print ("    [02] Aircrack-ng")
		print ("    [03] Airdecap-ng and Airdecloak-ng")
		print ("    [04] Aireplay-ng")
		print ("    [05] Airmon-ng")
		print ("    [06] Airodump-ng")
		print ("    [07] airodump-ng-oui-update")
		print ("    [08] Airolib-ng")
		print ("    [09] Airserv-ng")
		print ("    [10] Airtun-ng")
		print ("    [11] Asleap")
		print ("    [12] Besside-ng")
		print ("    [13] Bluelog")
		print ("    [14] BlueMaho")
		print ("    [15] Bluepot")
		print ("    [16] BlueRanger")
		print ("    [17] Bluesnarfer")
		print ("    [18] Bully")
		print ("    [19] coWPAtty")
		print ("    [20] crackle")
		print ("    [21] eapmd5pass")
		print ("    [22] Eassid-ng")
		print ("    [23] Fern Wifi Cracker")
		print ("    [24] FreeRADIUS-WPE")
		print ("    [25] Ghost Phisher")
		print ("    [26] GISKismet")
		print ("    [27] Gqrx")
		print ("    [28] gr-scan")
		print ("    [29] hostapd-wpe")
		print ("    [30] ivstools")
		print ("    [31] kalibrate-rtl")
		print ("    [32] KillerBee")
		print ("    [33] Kismet")
		print ("    [34] makeivs-ng")
		print ("    [35] mdk3")
		print ("    [36] mfcuk")
		print ("    [37] mfoc")
		print ("    [38] mfterm")
		print ("    [39] Multimon-NG")
		print ("    [40] Packetforge-ng")
		print ("    [41] PixieWPS")
		print ("    [42] Pyrit")
		print ("    [43] Reaver")
		print ("    [44] redfang")
		print ("    [45] RTLSDR Scanner")
		print ("    [46] Spooftooph")
		print ("    [47] Tkiptun-ng")
		print ("    [48] Wesside-ng")
		print ("    [49] Wifi Honey")
		print ("    [50] wifiphisher")
		print ("    [51] Wifitap")
		print ("    [52] Wifite")
		print ("    [53] wpaclean\n")
		print ("    [00] Back to main menu\n")
		wifiattack = input("kali > ")
		
		if wifiattack == "01" or wifiattack == "1":
			airbase_ng()
		elif wifiattack == "02" or wifiattack == "2":
			aircrack_ng()
		elif wifiattack == "03" or wifiattack == "3":
			airdecap_ng()
		elif wifiattack == "04" or wifiattack == "4":
			aireplay_ng()
		elif wifiattack == "05" or wifiattack == "5":
			airmon_ng()
		elif wifiattack == "06" or wifiattack == "6":
			airodump_ng()
		elif wifiattack == "07" or wifiattack == "7":
			airodump_ng_oui_update()
		elif wifiattack == "08" or wifiattack == "8":
			airolib_ng()
		elif wifiattack == "09" or wifiattack == "9":
			airserv_ng()
		elif wifiattack == "10":
			airtun_ng()
		elif wifiattack == "11":
			asleap()
		elif wifiattack == "12":
			besside_ng()
		elif wifiattack == "13":
			Bluelog()
		elif wifiattack == "14":
			bluemaho()
		elif wifiattack == "15":
			bluepot()
		elif wifiattack == "16":
			blueranger()
		elif wifiattack == "17":
			bluesnarfer()
		elif wifiattack == "18":
			bully()
		elif wifiattack == "19":
			cowpatty()
		elif wifiattack == "20":
			crackle()
		elif wifiattack == "21":
			eapmd5pass()
		elif wifiattack == "22":
			easside_ng()
		elif wifiattack == "23":
			fern_wifi_cracker()
		elif wifiattack == "24":
			freeradius_wpe()
		elif wifiattack == "25":
			ghost_phisher()
		elif wifiattack == "26":
			giskismet()
		elif wifiattack == "27":
			gqrx()
		elif wifiattack == "28":
			gr_scan()
		elif wifiattack == "29":
			hostapd_wpe()
		elif wifiattack == "30":
			ivstools()
		elif wifiattack == "31":
			kalibrate_rtl()
		elif wifiattack == "32":
			killerbee()
		elif wifiattack == "33":
			kismet()
		elif wifiattack == "34":
			makeivs_ng()
		elif wifiattack == "35":
			mdk3()
		elif wifiattack == "36":
			mfcuk()
		elif wifiattack == "37":
			mfoc()
		elif wifiattack == "38":
			mfterm()
		elif wifiattack == "39":
			multimon_ng()
		elif wifiattack == "40":
			packetforge_ng()
		elif wifiattack == "41":
			pixiewps()
		elif wifiattack == "42":
			pyrit()
		elif wifiattack == "43":
			reaver()
		elif wifiattack == "44":
			redfang()
		elif wifiattack == "45":
			rtlsdr_scanner()
		elif wifiattack == "46":
			spooftooph()
		elif wifiattack == "47":
			tkiptun_ng()
		elif wifiattack == "48":
			wesside_ng()
		elif wifiattack == "49":
			wifi_honey()
		elif wifiattack == "50":
			wifiphisher()
		elif wifiattack == "51":
			wifitap()
		elif wifiattack == "52":
			wifite()
		elif wifiattack == "53":
			wpaclean()
		elif wifiattack == "00" or wifiattack == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "4" or kali == "04":
		print ("\n    [01] apache_users")
		print ("    [02] Arachni")
		print ("    [03] BBQSQL")
		print ("    [04] BlindElephant")
		print ("    [05] Burp Suite")
		print ("    [06] CutyCapt")
		print ("    [07] DAVTest")
		print ("    [08] deblaze")
		print ("    [09] DIRB")
		print ("    [10] DirBuster")
		print ("    [11] fimap")
		print ("    [12] FunkLoad")
		print ("    [13] Gobuster")
		print ("    [14] Grabber")
		print ("    [15] hURL")
		print ("    [16] jboss-autopwn")
		print ("    [17] joomscan")
		print ("    [18] jSQL Injection")
		print ("    [19] Maltego Teeth")
		print ("    [20] Nikto")
		print ("    [21] PadBuster")
		print ("    [22] Paros")
		print ("    [23] Parsero")
		print ("    [24] plecost")
		print ("    [25] Powerfuzzer")
		print ("    [26] ProxyStrike")
		print ("    [27] Recon-ng")
		print ("    [28] Skipfish")
		print ("    [29] sqlmap")
		print ("    [30] Sqlninja")
		print ("    [31] sqlsus")
		print ("    [32] ua-tester")
		print ("    [33] Uniscan")
		print ("    [34] Vega")
		print ("    [35] w3af")
		print ("    [36] WebScarab")
		print ("    [37] Webshag")
		print ("    [38] WebSlayer")
		print ("    [39] WebSploit")
		print ("    [40] Wfuzz")
		print ("    [41] WhatWeb")
		print ("    [42] WPScan")
		print ("    [43] XSSer")
		print ("    [44] zaproxy\n")
		print ("    [00] Back to main menu\n")
		webapplications = input("kali > ")
		
		if webapplications == "01" or webapplications == "1":
			apache_users()
		elif webapplications == "02" or webapplications == "2":
			arachni()
		elif webapplications == "03" or webapplications == "3":
			bbqsql()
		elif webapplications == "04" or webapplications == "4":
			blindelephant()
		elif webapplications == "05" or webapplications == "5":
			burp_suite()
		elif webapplications == "06" or webapplications == "6":
			cutycapt()
		elif webapplications == "07" or webapplications == "7":
			davtest()
		elif webapplications == "08" or webapplications == "8":
			deblaze()
		elif webapplications == "09" or webapplications == "9":
			dirb()
		elif webapplications == "10":
			dirbuster()
		elif webapplications == "11":
			fimap()
		elif webapplications == "12":
			funkload()
		elif webapplications == "13":
			gobuster()
		elif webapplications == "14":
			grabber()
		elif webapplications == "15":
			hurl()
		elif webapplications == "16":
			jboss_autopwn()
		elif webapplications == "17":
			joomscan()
		elif webapplications == "18":
			jsql_injection()
		elif webapplications == "19":
			maltego_teeth()
		elif webapplications == "20":
			nikto()
		elif webapplications == "21":
			padbuster()
		elif webapplications == "22":
			paros()
		elif webapplications == "23":
			parsero()
		elif webapplications == "24":
			plecost()
		elif webapplications == "25":
			powerfuzzer()
		elif webapplications == "26":
			proxystrike()
		elif webapplications == "27":
			recon_ng()
		elif webapplications == "28":
			skipfish()
		elif webapplications == "29":
			sqlmap()
		elif webapplications == "30":
			sqlninja()
		elif webapplications == "31":
			sqlsus()
		elif webapplications == "32":
			ua_tester()
		elif webapplications == "33":
			uniscan()
		elif webapplications == "34":
			vega()
		elif webapplications == "35":
			w3af()
		elif webapplications == "36":
			webscarab()
		elif webapplications == "37":
			webshag()
		elif webapplications == "38":
			webslayer()
		elif webapplications == "39":
			websploit()
		elif webapplications == "40":
			wfuzz()
		elif webapplications == "41":
			whatweb()
		elif webapplications == "42":
			wpscan()
		elif webapplications == "43":
			xsser()
		elif webapplications == "44":
			zaproxy()
		elif webapplications == "00" or webapplications == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "5" or kali == "05":
		print ("\n    [01] Armitage")
		print ("    [02] Backdoor Factory")
		print ("    [03] BeEF")
		print ("    [04] cisco-auditing-tool")
		print ("    [05] cisco-global-exploiter")
		print ("    [06] cisco-ocs")
		print ("    [07] cisco-torch")
		print ("    [08] Commmix")
		print ("    [09] crackle")
		print ("    [10] exploitdb")
		print ("    [11] jboss-autopwn")
		print ("    [12] Linux Exploit Suggester")
		print ("    [13] Maltego Teeth")
		print ("    [14] Metasploit Framework")
		print ("    [15] MSFPC")
		print ("    [16] RouterSploit")
		print ("    [17] SET")
		print ("    [18] ShellNoob")
		print ("    [19] sqlmap")
		print ("    [20] THC-IPV6")
		print ("    [21] Yersinia\n")
		print ("    [00] Back to main menu\n")
		exploitationtools = input("kali > ")
		
		if exploitationtools == "01" or exploitationtools == "1":
			armitage()
		elif exploitationtools == "02" or exploitationtools == "2":
			backdoor_factory()
		elif exploitationtools == "03" or exploitationtools == "3":
			beef()
		elif exploitationtools == "04" or exploitationtools == "4":
			cisco_auditing_tool()
		elif exploitationtools == "05" or exploitationtools == "5":
			cisco_global_exploiter()
		elif exploitationtools == "06" or exploitationtools == "6":
			cisco_ocs()
		elif exploitationtools == "07" or exploitationtools == "7":
			cisco_torch()
		elif exploitationtools == "08" or exploitationtools == "8":
			commix()
		elif exploitationtools == "09" or exploitationtools == "9":
			crackle()
		elif exploitationtools == "10":
			exploitdb()
		elif exploitationtools == "11":
			jboss_autopwn()
		elif exploitationtools == "12":
			linux_exploit_suggester()
		elif exploitationtools == "13":
			maltego_teeth()
		elif exploitationtools == "14":
			metasploit_framework()
		elif exploitationtools == "15":
			msfpc()
		elif exploitationtools == "16":
			routersploit()
		elif exploitationtools == "17":
			set()
		elif exploitationtools == "18":
			shellnoob()
		elif exploitationtools == "19":
			sqlmap()
		elif exploitationtools == "20":
			thc_ipv6()
		elif exploitationtools == "21":
			yersinia()
		elif exploitationtools == "00" or exploitationtools == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "6" or kali == "06":
		print ("\n    [01] DHCPig")
		print ("    [02] FunkLoad")
		print ("    [03] iaxflood")
		print ("    [04] Inundator")
		print ("    [05] inviteflood")
		print ("    [06] ipv6-toolkit")
		print ("    [07] mdk3")
		print ("    [08] Reaver")
		print ("    [09] rtpflood")
		print ("    [10] SlowHTTPTest")
		print ("    [11] t50")
		print ("    [12] Termineter")
		print ("    [13] THC-IPV6")
		print ("    [14] THC-SSL-DOS")
		print ("    [00] Back to main menu\n")
		stresstesting = input("kali > ")
		
		if stresstesting == "01" or stresstesting == "1":
			dhcpig()
		elif stresstesting == "02" or stresstesting == "2":
			funkload()
		elif stresstesting == "03" or stresstesting == "3":
			iaxflood()
		elif stresstesting == "04" or stresstesting == "4":
			inundator()
		elif stresstesting == "05" or stresstesting == "5":
			inviteflood()
		elif stresstesting == "06" or stresstesting == "6":
			ipv6_toolkit()
		elif stresstesting == "07" or stresstesting == "7":
			mdk3()
		elif stresstesting == "08" or stresstesting == "8":
			reaver()
		elif stresstesting == "09" or stresstesting == "9":
			rtpflood()
		elif stresstesting == "10":
			slowhttptest()
		elif stresstesting == "11":
			t50()
		elif stresstesting == "12":
			terminater()
		elif stresstesting == "13":
			thc_ipv6()
		elif stresstesting == "14":
			thc_ssl_dos()
		elif stresstesting == "00" or stresstesting == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "7" or kali == "07":
		print ("\n    [01] Binwalk")
		print ("    [02] bulk-extractor")
		print ("    [03] Capstone")
		print ("    [04] chntpw")
		print ("    [05] Cuckoo")
		print ("    [06] dc3dd")
		print ("    [07] ddrescue")
		print ("    [08] DFF")
		print ("    [09] diStorm3")
		print ("    [10] Dumpzilla")
		print ("    [11] extundelete")
		print ("    [12] Foremost")
		print ("    [13] Galleta")
		print ("    [14] Guymager")
		print ("    [15] iPhone Backup Analyzer")
		print ("    [16] p0f")
		print ("    [17] pdf-parser")
		print ("    [18] pdfid")
		print ("    [19] pdgmail")
		print ("    [20] peepdf")
		print ("    [21] RegRipper")
		print ("    [22] Volatility")
		print ("    [23] Xplico")
		print ("    [00] Back to main menu\n")
		forensicstools = input("kali > ")
		
		if forensicstools == "01" or forensicstools == "1":
			binwalk()
		elif forensicstools == "02" or forensicstools == "2":
			bulk_extractor()
		elif forensicstools == "03" or forensicstools == "3":
			capstone()
		elif forensicstools == "04" or forensicstools == "4":
			chntpw()
		elif forensicstools == "05" or forensicstools == "5":
			cuckoo()
		elif forensicstools == "06" or forensicstools == "6":
			dc3dd()
		elif forensicstools == "07" or forensicstools == "7":
			ddrescue()
		elif forensicstools == "08" or forensicstools == "8":
			dff()
		elif forensicstools == "09" or forensicstools == "9":
			diStorm3()
		elif forensicstools == "10":
			dumpzilla()
		elif forensicstools == "11":
			extundelete()
		elif forensicstools == "12":
			foremost()
		elif forensicstools == "13":
			galleta()
		elif forensicstools == "14":
			guymager()
		elif forensicstools == "15":
			iphone_backup_analyzer()
		elif forensicstools == "16":
			p0f()
		elif forensicstools == "17":
			pdf_parser()
		elif forensicstools == "18":
			pdfid()
		elif forensicstools == "19":
			pdgmail()
		elif forensicstools == "20":
			peepdf()
		elif forensicstools == "21":
			regripper()
		elif forensicstools == "22":
			volatility()
		elif forensicstools == "23":
			xplico()
		elif forensicstools == "00" or forensicstools == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "8" or kali == "08":
		print ("\n    [01] Burp Suite")
		print ("    [02] DNSChef")
		print ("    [03] fixed")
		print ("    [04] hamster-sidejack")
		print ("    [05] HexInject")
		print ("    [06] iaxflood")
		print ("    [07] inviteflood")
		print ("    [08] iSMTP")
		print ("    [09] isr-evilgrade")
		print ("    [10] mitmproxy")
		print ("    [11] ohrwurm")
		print ("    [12] protos-sip")
		print ("    [13] rebind")
		print ("    [14] responder")
		print ("    [15] rtpbreak")
		print ("    [16] rtpinsertsound")
		print ("    [17] rtpmixsound")
		print ("    [18] sctpscan")
		print ("    [19] SIPArmyKnife")
		print ("    [20] SIPp")
		print ("    [21] SIPVicious")
		print ("    [22] Sniffjoke")
		print ("    [23] SSLsplit")
		print ("    [24] sslstrip")
		print ("    [25] THC-IPV6")
		print ("    [26] VOIPHopper")
		print ("    [27] WebScarab")
		print ("    [28] WifiHoney")
		print ("    [29] Wireshark")
		print ("    [30] xspy")
		print ("    [31] Yersinia")
		print ("    [32] zaproxy")
		print ("    [00] Back to main menu\n")
		sniffspoof = input("kali > ")
		
		if sniffspoof == "01" or sniffspoof == "1":
			burp_suite()
		elif sniffspoof == "02" or sniffspoof == "2":
			dnschef()
		elif sniffspoof == "03" or sniffspoof == "3":
			fiked()
		elif sniffspoof == "04" or sniffspoof == "4":
			hamster_sidejack()
		elif sniffspoof == "05" or sniffspoof == "5":
			hexinject()
		elif sniffspoof == "06" or sniffspoof == "6":
			iaxflood()
		elif sniffspoof == "07" or sniffspoof == "7":
			inviteflood()
		elif sniffspoof == "08" or sniffspoof == "8":
			ismtp()
		elif sniffspoof == "09" or sniffspoof == "9":
			isr_evilgrade()
		elif sniffspoof == "10":
			mitmproxy()
		elif sniffspoof == "11":
			ohrwurm()
		elif sniffspoof == "12":
			protos_sip()
		elif sniffspoof == "13":
			rebind()
		elif sniffspoof == "14":
			responder()
		elif sniffspoof == "15":
			rtpbreak()
		elif sniffspoof == "16":
			rtpinsertsound()
		elif sniffspoof == "17":
			rtpmixsound()
		elif sniffspoof == "18":
			sctpscan()
		elif sniffspoof == "19":
			siparmyknife()
		elif sniffspoof == "20":
			sipp()
		elif sniffspoof == "21":
			sipvicious()
		elif sniffspoof == "22":
			sniffjoke()
		elif sniffspoof == "23":
			sslsplit()
		elif sniffspoof == "24":
			sslstrip()
		elif sniffspoof == "25":
			thc_ipv6()
		elif sniffspoof == "26":
			voiphopper()
		elif sniffspoof == "27":
			webscarab()
		elif sniffspoof == "28":
			wifi_honey()
		elif sniffspoof == "29":
			wireshark()
		elif sniffspoof == "30":
			xspy()
		elif sniffspoof == "31":
			yersinia()
		elif sniffspoof == "32":
			zaproxy()
		elif sniffspoof == "00" or sniffspoof == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "9" or kali == "09":
		print ("\n    [01] acccheck")
		print ("    [02] BruteSpray")
		print ("    [03] Burp Suite")
		print ("    [04] CeWL")
		print ("    [05] chntpw")
		print ("    [06] cisco-auditing-tool")
		print ("    [07] CmosPwd")
		print ("    [08] creddump")
		print ("    [09] cowbar")
		print ("    [10] crunch")
		print ("    [11] DBPwAudit")
		print ("    [12] findmyhash")
		print ("    [13] gpp-decrypt")
		print ("    [14] hash-identifier")
		print ("    [15] Hashcat")
		print ("    [16] HexorBase")
		print ("    [17] THC-Hydra")
		print ("    [18] John the Ripper")
		print ("    [19] Johnny")
		print ("    [20] Keimpx")
		print ("    [21] Maltego Teeth")
		print ("    [22] Maskprocessor")
		print ("    [23] multiforce")
		print ("    [24] Ncrack")
		print ("    [25] oclgausscrack")
		print ("    [26] ophcrack")
		print ("    [27] PACK")
		print ("    [28] patator")
		print ("    [29] phrasendrescher")
		print ("    [30] polenum")
		print ("    [31] RainbowCrack")
		print ("    [32] rcracki-mt")
		print ("    [33] RSMangler")
		print ("    [34] SecLists")
		print ("    [35] SQLdict")
		print ("    [36] Statsprocessor")
		print ("    [37] THC-pptp-bruter")
		print ("    [38] TrueCrack")
		print ("    [39] WebScarab")
		print ("    [40] Wordlists")
		print ("    [41] zaproxy")
		print ("    [00] Back to main menu\n")
		passattack = input("kali > ")
		
		if passattack == "01" or passattack == "1":
			acccheck()
		elif passattack == "02" or passattack == "2":
			brutespray()
		elif passattack == "03" or passattack == "3":
			burp_suite()
		elif passattack == "04" or passattack == "4":
			cewl()
		elif passattack == "05" or passattack == "5":
			chntpw()
		elif passattack == "06" or passattack == "6":
			cisco_auditing_tool()
		elif passattack == "07" or passattack == "7":
			cmospwd()
		elif passattack == "08" or passattack == "8":
			creddump()
		elif passattack == "09" or passattack == "9":
			crowbar()
		elif passattack == "10":
			crunch()
		elif passattack == "11":
			dbpwaudit()
		elif passattack == "12":
			findmyhash()
		elif passattack == "13":
			gpp_decrypt()
		elif passattack == "14":
			hash_identifier()
		elif passattack == "15":
			hashcat()
		elif passattack == "16":
			hexorbase()
		elif passattack == "17":
			thc_hydra()
		elif passattack == "18":
			john_the_ripper()
		elif passattack == "19":
			johnny()
		elif passattack == "20":
			keimpx()
		elif passattack == "21":
			maltego_teeth()
		elif passattack == "22":
			maskprocessor()
		elif passattack == "23":
			multiforce()
		elif passattack == "24":
			ncrack()
		elif passattack == "25":
			oclgausscrack()
		elif passattack == "26":
			ophcrack()
		elif passattack == "27":
			pack()
		elif passattack == "28":
			patator()
		elif passattack == "29":
			phrasendrescher()
		elif passattack == "30":
			polenum()
		elif passattack == "31":
			rainbowcrack()
		elif passattack == "32":
			rcracki_mt()
		elif passattack == "33":
			rsmangler()
		elif passattack == "34":
			seclist()
		elif passattack == "35":
			sqldict()
		elif passattack == "36":
			statsprocessor()
		elif passattack == "37":
			thc_pptp_bruter()
		elif passattack == "38":
			truecrack()
		elif passattack == "39":
			webscarab()
		elif passattack == "40":
			wordlists()
		elif passattack == "41":
			zaproxy()
		elif passattack == "00" or passattack == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "10":
		print ("\n    [01] CryptCat")
		print ("    [02] Cymothoa")
		print ("    [03] dbd")
		print ("    [04] dns2tcp")
		print ("    [05] http-tunnel")
		print ("    [06] HTTPTunnel")
		print ("    [07] Intersect")
		print ("    [08] Nishang")
		print ("    [09] polenum")
		print ("    [10] PowerSploit")
		print ("    [11] pwnat")
		print ("    [12] RidEnum")
		print ("    [13] sbd")
		print ("    [14] shellter")
		print ("    [15] U3-Pwn")
		print ("    [16] Webshells")
		print ("    [17] Weevely")
		print ("    [18] Wineexe\n")
		print ("    [00] Back to main menu\n")
		maintainaccess = input("kali > ")
		
		if maintainaccess == "01" or maintainaccess == "1":
			cryptcat()
		elif maintainaccess == "02" or maintainaccess == "2":
			cymothoa()
		elif maintainaccess == "03" or maintainaccess == "3":
			dbd()
		elif maintainaccess == "04" or maintainaccess == "4":
			dns2tcp()
		elif maintainaccess == "05" or maintainaccess == "5":
			http_tunnel()
		elif maintainaccess == "06" or maintainaccess == "6":
			httptunnel()
		elif maintainaccess == "07" or maintainaccess == "7":
			intersect()
		elif maintainaccess == "08" or maintainaccess == "8":
			nishang()
		elif maintainaccess == "09" or maintainaccess == "9":
			polenum()
		elif maintainaccess == "10":
			powersploit()
		elif maintainaccess == "11":
			pwnat()
		elif maintainaccess == "12":
			ridenum()
		elif maintainaccess == "13":
			sbd()
		elif maintainaccess == "14":
			shellter()
		elif maintainaccess == "15":
			u3_pwn()
		elif maintainaccess == "16":
			webshells()
		elif maintainaccess == "17":
			weevely()
		elif maintainaccess == "18":
			winexe()
		elif maintainaccess == "00" or maintainaccess == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "11":
		print ("\n    [01] apktool")
		print ("    [02] dex2jar")
		print ("    [03] diStorm3")
		print ("    [04] edb-debugger")
		print ("    [05] jad")
		print ("    [06] javasnoop")
		print ("    [07] JD-GUI")
		print ("    [08] OllyDbg")
		print ("    [09] smali")
		print ("    [10] Valgrind")
		print ("    [11] YARA\n")
		print ("    [00] Back to main menu\n")
		reverseeng = input("kali > ")
		
		if reverseeng == "01" or reverseeng == "1":
			apktool()
		elif reverseeng == "02" or reverseeng == "2":
			dex2jar()
		elif reverseeng == "03" or reverseeng == "3":
			diStorm3()
		elif reverseeng == "04" or reverseeng == "4":
			edb_debugger()
		elif reverseeng == "05" or reverseeng == "5":
			jad()
		elif reverseeng == "06" or reverseeng == "6":
			javasnoop()
		elif reverseeng == "07" or reverseeng == "7":
			jd_gui()
		elif reverseeng == "08" or reverseeng == "8":
			ollydbg()
		elif reverseeng == "09" or reverseeng == "9":
			smali()
		elif reverseeng == "10":
			valgrind()
		elif reverseeng == "11":
			yara()
		elif reverseeng == "00" or reverseeng == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	elif kali == "12":
		print ("\n    [01] CaseFile")
		print ("    [02] cherrytree")
		print ("    [03] CutyCapt")
		print ("    [04] dos2unix")
		print ("    [05] Dradis")
		print ("    [06] MagicTree")
		print ("    [07] Metagoofil")
		print ("    [08] Nipper-ng")
		print ("    [09] pipal")
		print ("    [10] RDPY\n")
		print ("    [00] Back to main menu\n")
		reportingtools = input("kali > ")
		
		if reportingtools == "01" or reportingtools == "1":
			casefile()
		elif reportingtools == "02" or reportingtools == "2":
			cherrytree()
		elif reportingtools == "03" or reportingtools == "3":
			cutycapt()
		elif reportingtools == "04" or reportingtools == "4":
			dos2unix()
		elif reportingtools == "05" or reportingtools == "5":
			dradis()
		elif reportingtools == "06" or reportingtools == "6":
			magictree()
		elif reportingtools == "07" or reportingtools == "7":
			metagoofil()
		elif reportingtools == "08" or reportingtools == "8":
			nipper_ng()
		elif reportingtools == "09" or reportingtools == "9":
			pipal()
		elif reportingtools == "10":
			rdpy()
		elif reportingtools == "00" or reportingtools == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()
	
	elif kali == "13":
		print ("\n    [01] android-sdk")
		print ("    [02] apktool")
		print ("    [03] arduino")
		print ("    [04] dex2jar")
		print ("    [05] Sakis3G")
		print ("    [06] smail\n")
		print ("    [00] Back to main menu\n")
		reportingtools = input("kali > ")
		
		if reportingtools == "01" or reportingtools == "1":
			android_sdk()
		elif reportingtools == "02" or reportingtools == "2":
			apktool()
		elif reportingtools == "03" or reportingtools == "3":
			arduino()
		elif reportingtools == "04" or reportingtools == "4":
			dex2jar()
		elif reportingtools == "05" or reportingtools == "5":
			sakis3g()
		elif reportingtools == "06" or reportingtools == "6":
			smali()
		elif reportingtools == "00" or reportingtools == "0":
			restart_program()
		else:
			print ("\nERROR: Wrong Input")
			timeout(2)
			restart_program()

	elif kali == "00":
		sys.exit()
	
	else:
		print ("\nERROR: Wrong Input")
		timeout(2)
		restart_program()

if __name__ == "__main__":
	main()