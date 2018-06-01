## kali.py - useful module of Kali linux
import os
import sys
import time

kali_banner = """
.-.   .-.  .-.-.-.-.  .-.        .-.      .-.-.-.-.-.  .-.-.-.-.-.  .-.-.-.-.-.  .-.        .-.-.-.-.-.                                          
: :  : :   : .-.-. :  : :        : :      :-.-:-:-.-:  : ._._._. :  : ._._._. :  : :        : .-.-.-.-:                          
: : : :    : :_._: :  : :        : :          : :      : :     : :  : :     : :  : :        : :_._._._.                                
: : : :    :       :  : :        : :          : :      : :     : :  : :     : :  : :        :_._._._. :                   
: :  : :   : .-.-. :  : :-.-.-.  : :          : :      : :_._._. :  : :_._._. :  : :-.-.-.  :_._._._: :                                       
:_:   :_:  :_:   :_:  :_:_:_:_:  :_:          :_:      :_._._._._:  :_._._._._:  :_:_:_:_:  :_._._._._:                           



"""
backtomenu_banner = """
  [99] Back to main menu
  [00] Exit the Kali Tools
"""
def restart_program():
	python = sys.executable
	os.execl(python, python, * sys.argv)

def backtomenu_option():
	print (backtomenu_banner)
	backtomenu = raw_input("kali > ")
	
	if backtomenu == "99":
		restart_program()
	elif backtomenu == "00":
		sys.exit()
	else:
		print ("\nERROR: Wrong Input")
		time.sleep(2)
		restart_program()

def banner():
	print (kali_banner)

def acccheck():
	print ('\n###### Installing acccheck')
	os.system('apt-get install acccheck')
	print ('###### Done')
	print ("###### Type 'acccheck' to start.")
	backtomenu_option()

def ace_voip():
	print ('\n###### Installing ace-voip')
	os.system('apt-get install ace-voip')
	print ('###### Done')
	print ("###### Type 'ace-voip' to start.")
	backtomenu_option()

def amap():
	print ('\n###### Installing Amap')
	os.system('apt-get install amap')
	print ('###### Done')
	print ("###### Type 'amap' to start.")
	backtomenu_option()

def apt2():
	print ('\n###### Installing APT2')
	os.system('apt-get install apt2')
	print ('###### Done')
	print ("###### Type 'apt2' to start.")
	backtomenu_option()

def arp_scan():
	print ('\n###### Installing arp-scan')
	os.system('apt-get install arp-scan')
	print ('###### Done')
	print ("###### Type 'arp-scan' to start.")
	backtomenu_option()

def automater():
	print ('\n###### Installing Automater')
	os.system('apt-get install automater')
	print ('###### Done')
	print ("###### Type 'automater' to start.")
	backtomenu_option()

def bing_ip2hosts():
	print ('\n###### Installing bing-ip2hosts')
	os.system('apt-get install bing-ip2hosts')
	print ('###### Done')
	print ("###### Type 'bing-ip2hosts' to start.")
	backtomenu_option()

def braa():
	print ('\n###### Installing braa')
	os.system('apt-get install braa')
	print ('###### Done')
	print ("###### Type 'braa' to start.")
	backtomenu_option()

def casefile():
	print ('\n###### Installing CaseFile')
	os.system('apt-get install casefile')
	print ('###### Done')
	print ("###### Type 'casefile' to start.")
	backtomenu_option()

def cdpsnarf():
	print ('\n###### Installing CDPSnarf')
	os.system('apt-get install cdpsnarf')
	print ('###### Done')
	print ("###### Type 'cdpsnarf' to start.")
	backtomenu_option()

def cisco_torch():
	print ('\n###### Installing cisco-torch')
	os.system('apt-get install cisco-torch')
	print ('###### Done')
	print ("###### Type 'cisco-torch' to start.")
	backtomenu_option()

def cookie_cadger():
	print ('\n###### Installing Cookie Cadger')
	os.system('apt-get install cookie-cadger')
	print ('###### Done')
	print ("###### Type 'cookie-cadger' to start.")
	backtomenu_option()

def copy_router_config():
	print ('\n###### Installing copy-router-config')
	os.system("apt-get install copy-router-config")
	print ('###### Done')
	print ("###### Type 'copy-router-config.pl' to start.")
	backtomenu_option()

def dmitry():
	print ('\n###### Installing DMitry')
	os.system("apt-get install dmitry")
	print ('###### Done')
	print ("###### Type 'dmitry' to start.")
	backtomenu_option()

def dnmap():
	print ('\n###### Installing dnmap')
	os.system("apt-get install dnmap")
	print ('###### Done')
	print ("###### Type 'dnmap_client' or 'dnmap_server' to start.")
	backtomenu_option()

def dnsenum():
	print ('\n###### Installing dnsenum')
	os.system("apt-get install dnsenum")
	print ('###### Done')
	print ("###### Type 'dnsenum' to start.")
	backtomenu_option()

def dnsmap():
	print ('\n###### Installing dnsmap')
	os.system("apt-get install dnsmap")
	print ('###### Done')
	print ("###### Type 'dnsmap' to start.")
	backtomenu_option()

def dnsrecon():
	print ('\n###### Installing DNSRecon')
	os.system('apt-get install dnsrecon')
	print ('###### Done')
	print ("###### Type 'dnsrecon' to start.")
	backtomenu_option()

def dnstracer():
	print ('\n###### Installing dnstracer')
	os.system('apt-get install dnstracer')
	print ('###### Done')
	print ("###### Type 'dnsrecon' to start.")
	backtomenu_option()

def dnswalk():
	print ('\n###### Installing dnswalk')
	os.system('apt-get install dnswalk')
	print ('###### Done')
	print ("###### Type 'dnswalk' to start.")
	backtomenu_option()

def dotdotpwn():
	print ('\n###### Installing DotDotPwn')
	os.system('apt-get install dotdotpwn')
	print ('###### Done')
	print ("###### Type 'dotdotpwn' to start.")
	backtomenu_option()

def enum4linux():
	print ('\n###### Installing enum4linux')
	os.system('apt-get install enum4linux')
	print ('###### Done')
	print ("###### Type 'enum4linux' to start.")
	backtomenu_option()

def enumiax():
	print ('\n###### Installing enumIAX')
	os.system('apt-get install enumiax')
	print ('###### Done')
	print ("###### Type 'enumiax' to start.")
	backtomenu_option()

def eyewitness():
	print ('\n###### Installing EyeWitness')
	os.system('apt-get install eyewitness')
	print ('###### Done')
	print ("###### Type 'eyewitess' to start.")
	backtomenu_option()

def faraday():
	print ('\n###### Installing ')
	os.system('apt-get install python-faraday')
	print ('###### Done')
	print ("###### Type 'python-faraday' to start.")
	backtomenu_option()

def fierce():
	print ('\n###### Installing fierce')
	os.system('apt-get install fierce')
	print ('###### Done')
	print ("###### Type 'fierce' to start.")
	backtomenu_option()

def firewalk():
	print ('\n###### Installing Firewalk')
	os.system('apt-get install firewalk')
	print ('###### Done')
	print ("###### Type 'firewalk' to start.")
	backtomenu_option()

def fragroute():
	print ('\n###### Installing fragroute')
	os.system('apt-get install fragroute')
	print ('###### Done')
	print ("###### Type 'fragroute' to start.")
	backtomenu_option()

def fragrouter():
	print ('\n###### Installing fragrouter')
	os.system('apt-get install fragrouter')
	print ('###### Done')
	print ("###### Type 'fragrouter' to start.")
	backtomenu_option()

def ghost_phisher():
	print ('\n###### Installing Ghost Phisher')
	os.system('apt-get install ghost-phisher')
	print ('###### Done')
	print ("###### Type 'ghost-phisher' to start.")
	backtomenu_option()

def golismero():
	print ('\n###### Installing GoLismero')
	os.system('apt-get install golismero')
	print ('###### Done')
	print ("###### Type 'golismero' to start.")
	backtomenu_option()

def goofile():
	print ('\n###### Installing goofile')
	os.system('apt-get install goofile')
	print ('###### Done')
	print ("###### Type 'goofile' to start.")
	backtomenu_option()

def hping3():
	print ('\n###### Installing hping3')
	os.system('apt-get install hping3')
	print ('###### Done')
	print ("###### Type 'hping3' to start.")
	backtomenu_option()

def ident_user_enum():
	print ('\n###### Installing ident-user-enum')
	os.system('apt-get install ident-user-enum')
	print ('###### Done')
	print ("###### Type 'ident-user-enum' to start.")
	backtomenu_option()

def inspy():
	print ('\n###### Installing InSpy')
	os.system('apt-get install inspy')
	print ('###### Done')
	print ("###### Type 'inspy' to start.")
	backtomenu_option()

def intrace():
	print ('\n###### Installing InTrace')
	os.system('apt-get install intrace')
	print ('###### Done')
	print ("###### Type 'intrace' to start.")
	backtomenu_option()

def ismtp():
	print ('\n###### Installing iSMTP')
	os.system('apt-get install ismtp')
	print ('###### Done')
	print ("###### Type 'ismtp' to start.")
	backtomenu_option()

def ibd():
	print ('\n###### Installing Ibd')
	os.system('apt-get install ibd')
	print ('###### Done')
	print ("###### Type 'ibd' to start.")
	backtomenu_option()

def maltego_teeth():
	print ('\n###### Installing Maltego Teeth')
	os.system('apt-get install maltego-teeth')
	print ('###### Done')
	print ("###### Type 'maltego-teeth' to start.")
	backtomenu_option()

def masscan():
	print ('\n###### Installing masscan')
	os.system('apt-get install masscan')
	print ('###### Done')
	print ("###### Type 'masscan' to start.")
	backtomenu_option()

def metagoofil():
	print ('\n###### Installing Metagoofil')
	os.system('apt-get install metagoofil')
	print ('###### Done')
	print ("###### Type 'metagoofil' to start.")
	backtomenu_option()

def miranda():
	print ('\n###### Installing Miranda')
	os.system('apt-get install miranda')
	print ('###### Done')
	print ("###### Type 'miranda' to start.")
	backtomenu_option()

def nbtscan_unixwiz():
	print ('\n###### Installing nbtscan-unixwiz')
	os.system('apt-get install nbtscan-unixwiz')
	print ('###### Done')
	print ("###### Type 'nbtscan-unixwiz' to start.")
	backtomenu_option()

def nikto():
	print ('\n###### Installing Nikto')
	os.system('apt-get install nikto')
	print ('###### Done')
	print ("###### Type 'nikto' to start.")
	backtomenu_option()

def nmap():
	print ('\n###### Installing nmap')
	os.system('apt-get install nmap')
	print ('###### Done')
	print ("###### Type 'nping', 'ndiff', 'ncat', 'nmap' to start.")
	backtomenu_option()

def ntop():
	print ('\n###### Installing ntop')
	os.system('apt-get install ntop')
	print ('###### Done')
	print ("###### Type 'ntop' to start.")
	backtomenu_option()

def osrframework():
	print ('\n###### Installing OSRFramework')
	os.system('apt-get install osrframework')
	print ('###### Done')
	print ("###### Type 'osrframework' to start.")
	backtomenu_option()

def p0f():
	print ('\n###### Installing p0f')
	os.system('apt-get install p0f')
	print ('###### Done')
	print ("###### Type 'p0f' to start.")
	backtomenu_option()

def parsero():
	print ('\n###### Installing parsero')
	os.system('apt-get install Parsero')
	print ('###### Done')
	print ("###### Type 'parsero' to start.")
	backtomenu_option()

def recon_ng():
	print ('\n###### Installing recon-ng')
	os.system('apt-get install recon-ng')
	print ('###### Done')
	print ("###### Type 'recon-ng' to start.")
	backtomenu_option()

def set():
	print ('\n###### Installing setoolkit')
	os.system('apt-get install set')
	print ('###### Done')
	print ("###### Type 'set' to start.")
	backtomenu_option()

def smbmap():
	print ('\n###### Installing SMBMap')
	os.system('apt-get install smbmap')
	print ('###### Done')
	print ("###### Type 'smbmap' to start.")
	backtomenu_option()

def smtp_user_enum():
	print ('\n###### Installing smtp-user-enum')
	os.system('apt-get install smtp-user-enum')
	print ('###### Done')
	print ("###### Type 'smtp-user-enum' to start.")
	backtomenu_option()

def snmp_check():
	print ('\n###### Installing snmp-check')
	os.system('apt-get install snmp-check')
	print ('###### Done')
	print ("###### Type 'snmp-check' to start.")
	backtomenu_option()

def sparta():
	print ('\n###### Installing SPARTA')
	os.system('apt-get install sparta')
	print ('###### Done')
	print ("###### Type 'sparta' to start.")
	backtomenu_option()

def sslcaudit():
	print ('\n###### Installing sslcaudit')
	os.system('apt-get install sslcaudit')
	print ('###### Done')
	print ("###### Type 'sslcaudit' to start.")
	backtomenu_option()

def sslsplit():
	print ('\n###### Installing SSLsplit')
	os.system('apt-get install sslsplit')
	print ('###### Done')
	print ("###### Type 'sslsplit' to start.")
	backtomenu_option()

def sslstrip():
	print ('\n###### Installing SSLstrip')
	os.system('apt-get install sslstrip')
	print ('###### Done')
	print ("###### Type 'sslstrip' to start.")
	backtomenu_option()

def sslyze():
	print ('\n###### Installing SSLyze')
	os.system('apt-get install sslyze')
	print ('###### Done')
	print ("###### Type 'sslyze' to start.")
	backtomenu_option()

def sublist3r():
	print ('\n###### Installing sublist3r')
	os.system('apt-get install sublist3r')
	print ('###### Done')
	print ("###### Type 'sublist3r' to start.")
	backtomenu_option()

def thc_ipv6():
	print ('\n###### Installing THC-IPV6')
	os.system('apt-get install thc-ipv6')
	print ('###### Done')
	print ("###### Type 'thc-ipv6' to start.")
	backtomenu_option()

def theharvester():
	print ('\n###### Installing theHarvester')
	os.system('apt-get install theharvester')
	print ('###### Done')
	print ("###### Type 'theharvester' to start.")
	backtomenu_option()

def tlssled():
	print ('\n###### Installing TLSSLed')
	os.system('apt-get install tlssled')
	print ('###### Done')
	print ("###### Type 'tlssled' to start.")
	backtomenu_option()

def twofi():
	print ('\n###### Installing twofi')
	os.system('apt-get install twofi')
	print ('###### Done')
	print ("###### Type 'twofi' to start.")
	backtomenu_option()

def unicornscan():
	print ('\n###### Installing Unicornscan')
	os.system('apt-get install unicornscan')
	print ('###### Done')
	print ("###### Type 'unicornscan' to start.")
	backtomenu_option()

def urlcrazy():
	print ('\n###### Installing urlcrazy')
	os.system('apt-get install urlcrazy')
	print ('###### Done')
	print ("###### Type 'urlcrazy' to start.")
	backtomenu_option()

def wireshark():
	print ('\n###### Installing Wireshark')
	os.system('apt-get install wireshark')
	print ('###### Done')
	print ("###### Type 'wireshark' to start.")
	backtomenu_option()

def wol_e():
	print ('\n###### Installing WOL-E')
	os.system('apt-get install wol-e')
	print ('###### Done')
	print ("###### Type 'wol-e' to start.")
	backtomenu_option()

def xplico():
	print ('\n###### Installing Xplico')
	os.system('apt-get install xplico')
	print ('###### Done')
	print ("###### Type 'xplico' to start.")
	backtomenu_option()

def bbqsql():
	print ('\n###### Installing BBQSQL')
	os.system('apt-get install bbqsql')
	print ('###### Done')
	print ("###### Type 'bbqsql' to start.")
	backtomenu_option()

def bed():
	print ('\n###### Installing BED')
	os.system('apt-get install bed')
	print ('###### Done')
	print ("###### Type 'bed' to start.")
	backtomenu_option()

def cisco_auditing_tool():
	print ('\n###### Installing cisco-auditing-tool')
	os.system('apt-get install cisco-auditing-tool')
	print ('###### Done')
	print ("###### Type 'cat' to start.")
	backtomenu_option()

def cisco_global_exploiter():
	print ('\n###### Installing cisco-global-exploiter')
	os.system('apt-get install cisco-global-exploiter')
	print ('###### Done')
	print ("###### Type 'cge.pl' to start.")
	backtomenu_option()

def cisco_ocs():
	print ('\n###### Installing cisco-ocs')
	os.system('apt-get install cisco-ocs')
	print ('###### Done')
	print ("###### Type 'cisco-ocs' to start.")
	backtomenu_option()

def dbpwaudit():
	print ('\n###### Installing DBPwAudit')
	os.system('apt-get install dbpwaudit')
	print ('###### Done')
	print ("###### Type 'dbpwaudit' to start.")
	backtomenu_option()

def doona():
	print ('\n###### Installing Doona')
	os.system('apt-get install doona')
	print ('###### Done')
	print ("###### Type 'doona' to start.")
	backtomenu_option()

def hexorbase():
	print ('\n###### Installing HexorBase')
	os.system('apt-get install hexorbase')
	print ('###### Done')
	print ("###### Type 'hexorbase' to start.")
	backtomenu_option()

def inguma():
	print ('\n###### Installing Inguma')
	os.system('apt-get install inguma')
	print ('###### Done')
	print ("###### Type 'inguma' to start.")
	backtomenu_option()

def jsql_injection():
	print ('\n###### Installing JSQL Injection')
	os.system('apt-get install jsql')
	print ('###### Done')
	print ("###### Type 'jsql' to start.")
	backtomenu_option()

def lynis():
	print ('\n###### Installing Lynis')
	os.system('apt-get install lynis')
	print ('###### Done')
	print ("###### Type 'lynis' to start.")
	backtomenu_option()

def ohrwurm():
	print ('\n###### Installing ohrwurm')
	os.system('apt-get install ohrwurm')
	print ('###### Done')
	print ("###### Type 'ohrwurm' to start.")
	backtomenu_option()

def openvas():
	print ('\n###### Installing openvas')
	os.system('apt-get install openvas')
	print ('###### Done')
	print ("###### Type 'openvas' to start.")
	backtomenu_option()

def oscanner():
	print ('\n###### Installing Oscanner')
	os.system('apt-get install oscanner')
	print ('###### Done')
	print ("###### Type 'oscanner' to start.")
	backtomenu_option()

def powerfuzzer():
	print ('\n###### Installing Powerfuzzer')
	os.system('apt-get install powerfuzzer')
	print ('###### Done')
	print ("###### Type 'powerfuzzer' to start.")
	backtomenu_option()

def sfuzz():
	print ('\n###### Installing sfuzz')
	os.system('apt-get install sfuzz')
	print ('###### Done')
	print ("###### Type 'sfuzz' to start.")
	backtomenu_option()

def sidguesser():
	print ('\n###### Installing SidGuesser')
	os.system('apt-get install sidguesser')
	print ('###### Done')
	print ("###### Type 'sidguesser' to start.")
	backtomenu_option()

def siparmyknife():
	print ('\n###### Installing SIPArmyKnife')
	os.system('apt-get install siparmyknife')
	print ('###### Done')
	print ("###### Type 'siparmyknife' to start.")
	backtomenu_option()

def sqlmap():
	print ('\n###### Installing sqlmap')
	os.system('apt-get install sqlmap')
	print ('###### Done')
	print ("###### Type 'sqlmap' to start.")
	backtomenu_option()

def sqlninja():
	print ('\n###### Installing Sqlninja')
	os.system('apt-get install sqlninja')
	print ('###### Done')
	print ("###### Type 'sqlninja' to start.")
	backtomenu_option()

def sqlsus():
	print ('\n###### Installing sqlsus')
	os.system('apt-get install sqlsus')
	print ('###### Done')
	print ("###### Type 'sqlsus' to start.")
	backtomenu_option()

def tnscmd10g():
	print ('\n###### Installing tnscmd10g')
	os.system('apt-get install tnscmd10g')
	print ('###### Done')
	print ("###### Type 'tnscmd10g' to start.")
	backtomenu_option()

def unix_privesc_check():
	print ('\n###### Installing unix-privesc-check')
	os.system('apt-get install unix-privesc-check')
	print ('###### Done')
	print ("###### Type 'unix-privesc-check' to start.")
	backtomenu_option()

def yersinia():
	print ('\n###### Installing Yersinia')
	os.system('apt-get install yersinia')
	print ('###### Done')
	print ("###### Type 'yersinia' to start.")
	backtomenu_option()

def airbase_ng():
	print ('\n###### Installing Airbase-ng')
	os.system('apt-get install airbase-ng')
	print ('###### Done')
	print ("###### Type 'airbase-ng' to start.")
	backtomenu_option()

def aircrack_ng():
	print ('\n###### Installing Aircrack-ng')
	os.system('apt-get install aircrack-ng')
	print ('###### Done')
	print ("###### Type 'aircrack-ng' to start.")
	backtomenu_option()

def airdecap_ng():
	print ('\n###### Installing Airdecap-ng')
	os.system('apt-get install airdecap-ng')
	print ('###### Done')
	os.system('apt-get install airdecloak-ng')
	print ('###### Done')	
	print ("###### Type 'airdecap-ng' or 'airdecloak-ng' to start.")
	backtomenu_option()

def aireplay_ng():
	print ('\n###### Installing Aireplay-ng')
	os.system('apt-get install aireplay-ng')
	print ('###### Done')
	print ("###### Type 'aireplay-ng' to start.")
	backtomenu_option()

def airmon_ng():
	print ('\n###### Installing airmon-ng')
	os.system('apt-get install airmon-ng')
	print ('###### Done')
	print ("###### Type 'airmon-ng' to start.")
	backtomenu_option()

def airodump_ng():
	print ('\n###### Installing airodump-ng')
	os.system('apt-get install airodump-ng')
	print ('###### Done')
	print ("###### Type 'airodump-ng' to start.")
	backtomenu_option()

def airodump_ng_oui_update():
	print ('\n###### Installing airodump-ng-oui-update')
	os.system('apt-get install airodump-ng-oui-update')
	print ('###### Done')
	print ("###### Type 'airodump-ng-oui-update' to start.")
	backtomenu_option()

def airolib_ng():
	print ('\n###### Installing Airolib-ng')
	os.system('apt-get install airolib-ng')
	print ('###### Done')
	print ("###### Type 'airolib-ng' to start.")
	backtomenu_option()

def airserv_ng():
	print ('\n###### Installing Airserv-ng')
	os.system('apt-get install airserv-ng')
	print ('###### Done')
	print ("###### Type 'airserv-ng' to start.")
	backtomenu_option()

def airtun_ng():
	print ('\n###### Installing Airtun-ng')
	os.system('apt-get install airtun-ng')
	print ('###### Done')
	print ("###### Type 'airtun-ng' to start.")
	backtomenu_option()

def asleap():
	print ('\n###### Installing Asleap')
	os.system('apt-get install asleap')
	print ('###### Done')
	print ("###### Type 'asleap' to start.")
	backtomenu_option()

def besside_ng():
	print ('\n###### Installing Besside-ng')
	os.system('apt-get install besside-ng')
	print ('###### Done')
	print ("###### Type 'besside-ng' to start.")
	backtomenu_option()

def Bluelog():
	print ('\n###### Installing Bluelog')
	os.system('apt-get install bluelog')
	print ('###### Done')
	print ("###### Type 'bluelog' to start.")
	backtomenu_option()

def bluemaho():
	print ('\n###### Installing BlueMaho')
	os.system('apt-get install bluemaho')
	print ('###### Done')
	print ("###### Type 'bluemaho' to start.")
	backtomenu_option()

def bluepot():
	print ('\n###### Installing Bluepot')
	os.system('apt-get install Bluepot')
	print ('###### Done')
	print ("###### Type 'bluepot' to start.")
	backtomenu_option()

def blueranger():
	print ('\n###### Installing BlueRanger')
	os.system('apt-get install ')
	print ('###### Done')
	print ("###### Type 'blueranger' to start.")
	backtomenu_option()

def bluesnarfer():
	print ('\n###### Installing Bluesnarfer')
	os.system('apt-get install bluesnarfer')
	print ('###### Done')
	print ("###### Type 'bluesnarfer' to start.")
	backtomenu_option()

def bully():
	print ('\n###### Installing Bully')
	os.system('apt-get install bully')
	print ('###### Done')
	print ("###### Type 'Bully' to start.")
	backtomenu_option()

def cowpatty():
	print ('\n###### Installing coWPAtty')
	os.system('apt-get install cowpatty')
	print ('###### Done')
	print ("###### Type 'cowpatty' to start.")
	backtomenu_option()

def crackle():
	print ('\n###### Installing Crackle')
	os.system('apt-get install crackle')
	print ('###### Done')
	print ("###### Type 'crackle' to start.")
	backtomenu_option()

def eapmd5pass():
	print ('\n###### Installing eapmd5pass')
	os.system('apt-get install eapmd5pass')
	print ('###### Done')
	print ("###### Type 'eapmd5pass' to start.")
	backtomenu_option()

def easside_ng():
	print ('\n###### Installing Easside-ng')
	os.system('apt-get install easside-ng')
	print ('###### Done')
	print ("###### Type 'easside-ng' to start.")
	backtomenu_option()

def fern_wifi_cracker():
	print ('\n###### Installing ')
	os.system('apt-get install ')
	print ('###### Done')
	print ("###### Type '' to start.")
	backtomenu_option()

def freeradius_wpe():
	print ('\n###### Installing freeRADIUS-wpe')
	os.system('apt-get install freeradius-wpe')
	print ('###### Done')
	print ("###### Type 'freeradius-wpe' to start.")
	backtomenu_option()

def giskismet():
	print ('\n###### Installing GISKismet')
	os.system('apt-get install giskismet')
	print ('###### Done')
	print ("###### Type 'giskismet' to start.")
	backtomenu_option()

def gqrx():
	print ('\n###### Installing Gqrx')
	os.system('apt-get install gqrx')
	print ('###### Done')
	print ("###### Type 'gqrx' to start.")
	backtomenu_option()

def gr_scan():
	print ('\n###### Installing gr-scan')
	os.system('apt-get install gr-scan')
	print ('###### Done')
	print ("###### Type 'gr-scan' to start.")
	backtomenu_option()

def hostapd_wpe():
	print ('\n###### Installing hostapd-wpe')
	os.system('apt-get install hostapd-wpe')
	print ('###### Done')
	print ("###### Type 'hostapd-wpe' to start.")
	backtomenu_option()

def ivstools():
	print ('\n###### Installing ivstools')
	os.system('apt-get install ivstools')
	print ('###### Done')
	print ("###### Type 'ivstools' to start.")
	backtomenu_option()

def kalibrate_rtl():
	print ('\n###### Installing kalibrate-rtl')
	os.system('apt-get install kalibrate-rtl')
	print ('###### Done')
	print ("###### Type 'kalibrate-rtl' to start.")
	backtomenu_option()

def killerbee():
	print ('\n###### Installing KillerBee')
	os.system('apt-get install killerbee')
	print ('###### Done')
	print ("###### Type 'killerbee' to start.")
	backtomenu_option()

def kismet():
	print ('\n###### Installing Kismet')
	os.system('apt-get install kismet')
	print ('###### Done')
	print ("###### Type 'kilsmet' to start.")
	backtomenu_option()

def makeivs_ng():
	print ('\n###### Installing makeivs-ng')
	os.system('apt-get install makeivs-ng')
	print ('###### Done')
	print ("###### Type 'makeivs-ng' to start.")
	backtomenu_option()

def mdk3():
	print ('\n###### Installing mdk3')
	os.system('apt-get install mdk3')
	print ('###### Done')
	print ("###### Type 'mdk3' to start.")
	backtomenu_option()

def mfcuk():
	print ('\n###### Installing mfcuk')
	os.system('apt-get install mfcuk')
	print ('###### Done')
	print ("###### Type 'mfcuk' to start.")
	backtomenu_option()

def mfoc():
	print ('\n###### Installing mfoc')
	os.system('apt-get install mfoc')
	print ('###### Done')
	print ("###### Type 'mfoc' to start.")
	backtomenu_option()

def mfterm():
	print ('\n###### Installing mfterm')
	os.system('apt-get install mfterm')
	print ('###### Done')
	print ("###### Type 'mfterm' to start.")
	backtomenu_option()

def multimon_ng():
	print ('\n###### Installing Multimon-NG')
	os.system('apt-get install multimon-ng')
	print ('###### Done')
	print ("###### Type 'multimon-ng' to start.")
	backtomenu_option()

def packetforge_ng():
	print ('\n###### Installing Packetforge-ng')
	os.system('apt-get install packetforge-ng')
	print ('###### Done')
	print ("###### Type 'packetforge-ng' to start.")
	backtomenu_option()

def pixiewps():
	print ('\n###### Installing PixieWPS')
	os.system('apt-get install pixiewps')
	print ('###### Done')
	print ("###### Type 'pixiewps' to start.")
	backtomenu_option()

def pyrit():
	print ('\n###### Installing Pyrit')
	os.system('apt-get install pyrit')
	print ('###### Done')
	print ("###### Type 'pyrit' to start.")
	backtomenu_option()

def reaver():
	print ('\n###### Installing Reaver')
	os.system('apt-get install reaver')
	print ('###### Done')
	print ("###### Type 'reaver' to start.")
	backtomenu_option()

def redfang():
	print ('\n###### Installing redfang')
	os.system('apt-get install redfang')
	print ('###### Done')
	print ("###### Type 'redfang' to start.")
	backtomenu_option()

def rtlsdr_scanner():
	print ('\n###### Installing RTLSDR Scanner')
	os.system('apt-get install rtlsdr-scanner')
	print ('###### Done')
	print ("###### Type 'rtlsdr-scanner' to start.")
	backtomenu_option()

def spooftooph():
	print ('\n###### Installing Spooftooph')
	os.system('apt-get install spooftooph')
	print ('###### Done')
	print ("###### Type 'spooftooph' to start.")
	backtomenu_option()

def tkiptun_ng():
	print ('\n###### Installing Tkiptun-ng')
	os.system('apt-get install tkiptun-ng')
	print ('###### Done')
	print ("###### Type 'tkiptun-ng' to start.")
	backtomenu_option()

def wesside_ng():
	print ('\n###### Installing Wesside-ng')
	os.system('apt-get install wesside-ng')
	print ('###### Done')
	print ("###### Type 'wesside-ng' to start.")
	backtomenu_option()

def wifi_honey():
	print ('\n###### Installing Wifi-honey')
	os.system('apt-get install wifi-honey')
	print ('###### Done')
	print ("###### Type 'wifi-honey' to start.")
	backtomenu_option()

def wifiphisher():
	print ('\n###### Installing wifiphisher')
	os.system('apt-get install wifiphisher')
	print ('###### Done')
	print ("###### Type 'wifiphisher' to start.")
	backtomenu_option()

def wifitap():
	print ('\n###### Installing Wifitap')
	os.system('apt-get install wifitap')
	print ('###### Done')
	print ("###### Type 'wifitap' to start.")
	backtomenu_option()

def wifite():
	print ('\n###### Installing Wifite')
	os.system('apt-get install wifite')
	print ('###### Done')
	print ("###### Type 'wifite' to start.")
	backtomenu_option()

def wpaclean():
	print ('\n###### Installing wpaclean')
	os.system('apt-get install wpaclean')
	print ('###### Done')
	print ("###### Type 'wpaclean' to start.")
	backtomenu_option()

def apache_users():
	print ('\n###### Installing apache-users')
	os.system('apt-get install apache-users')
	print ('###### Done')
	print ("###### Type 'apache-users' to start.")
	backtomenu_option()

def arachni():
	print ('\n###### Installing Arachni')
	os.system('apt-get install arachni')
	print ('###### Done')
	print ("###### Type 'arachni' to start.")
	backtomenu_option()

def blindelephant():
	print ('\n###### Installing BlindElephant')
	os.system('apt-get install blindelephant')
	print ('###### Done')
	print ("###### Type 'blindelephant' to start.")
	backtomenu_option()

def burp_suite():
	print ('\n###### Installing Burp Suite')
	os.system('apt-get install burp-suite')
	print ('###### Done')
	print ("###### Type 'burp-suite' to start.")
	backtomenu_option()

def cutycapt():
	print ('\n###### Installing CutyCapt')
	os.system('apt-get install cutycapt')
	print ('###### Done')
	print ("###### Type 'cutycapt' to start.")
	backtomenu_option()

def davtest():
	print ('\n###### Installing DAVTest')
	os.system('apt-get install davtest')
	print ('###### Done')
	print ("###### Type 'davtest' to start.")
	backtomenu_option()

def deblaze():
	print ('\n###### Installing deblaze')
	os.system('apt-get install deblaze')
	print ('###### Done')
	print ("###### Type 'deblaze' to start.")
	backtomenu_option()

def dirb():
	print ('\n###### Installing DIRB')
	os.system('apt-get install dirb')
	print ('###### Done')
	print ("###### Type 'dirb' to start.")
	backtomenu_option()

def dirbuster():
	print ('\n###### Installing DirBuster')
	os.system('apt-get install dirbuster')
	print ('###### Done')
	print ("###### Type 'dirbuster' to start.")
	backtomenu_option()

def fimap():
	print ('\n###### Installing fimap')
	os.system('apt-get install fimap')
	print ('###### Done')
	print ("###### Type 'fimap' to start.")
	backtomenu_option()

def funkload():
	print ('\n###### Installing FunkLoad')
	os.system('apt-get install funkload')
	print ('###### Done')
	print ("###### Type 'funkload' to start.")
	backtomenu_option()

def gobuster():
	print ('\n###### Installing Gobuster')
	os.system('apt-get install gobuster')
	print ('###### Done')
	print ("###### Type 'gobuster' to start.")
	backtomenu_option()

def grabber():
	print ('\n###### Installing Grabber')
	os.system('apt-get install grabber')
	print ('###### Done')
	print ("###### Type 'grabber' to start.")
	backtomenu_option()

def hurl():
	print ('\n###### Installing hURL')
	os.system('apt-get install hurl')
	print ('###### Done')
	print ("###### Type 'hurl' to start.")
	backtomenu_option()

def jboss_autopwn():
	print ('\n###### Installing jboss-autopwn')
	os.system('apt-get install jboss-autopwn')
	print ('###### Done')
	print ("###### Type 'jboss-autopwn' to start.")
	backtomenu_option()

def joomscan():
	print ('\n###### Installing joomscan')
	os.system('apt-get install joomscan')
	print ('###### Done')
	print ("###### Type 'joomscan' to start.")
	backtomenu_option()

def padbuster():
	print ('\n###### Installing PadBuster')
	os.system('apt-get install padbuster')
	print ('###### Done')
	print ("###### Type 'padbuster' to start.")
	backtomenu_option()

def paros():
	print ('\n###### Installing Paros')
	os.system('apt-get install paros')
	print ('###### Done')
	print ("###### Type 'paros' to start.")
	backtomenu_option()

def plecost():
	print ('\n###### Installing plecost')
	os.system('apt-get install plecost')
	print ('###### Done')
	print ("###### Type 'plecost' to start.")
	backtomenu_option()

def proxystrike():
	print ('\n###### Installing ProxyStrike')
	os.system('apt-get install proxystrike')
	print ('###### Done')
	print ("###### Type 'proxystrike' to start.")
	backtomenu_option()

def skipfish():
	print ('\n###### Installing Skipfish')
	os.system('apt-get install skipfish')
	print ('###### Done')
	print ("###### Type 'skipfish' to start.")
	backtomenu_option()

def ua_tester():
	print ('\n###### Installing ua-tester')
	os.system('apt-get install ua-tester')
	print ('###### Done')
	print ("###### Type 'ua-tester' to start.")
	backtomenu_option()

def uniscan():
	print ('\n###### Installing Uniscan')
	os.system('apt-get install uniscan')
	print ('###### Done')
	print ("###### Type 'uniscan' to start.")
	backtomenu_option()

def vega():
	print ('\n###### Installing Vega')
	os.system('apt-get install vega')
	print ('###### Done')
	print ("###### Type 'vega' to start.")
	backtomenu_option()

def w3af():
	print ('\n###### Installing w3af')
	os.system('apt-get install w3af')
	print ('###### Done')
	print ("###### Type 'w3af' to start.")
	backtomenu_option()

def webscarab():
	print ('\n###### Installing WebScarab')
	os.system('apt-get install webscarab')
	print ('###### Done')
	print ("###### Type 'webscarab' to start.")
	backtomenu_option()

def webshag():
	print ('\n###### Installing Webshag')
	os.system('apt-get install webshag')
	print ('###### Done')
	print ("###### Type 'webshag' to start.")
	backtomenu_option()

def webslayer():
	print ('\n###### Installing WebSlayer')
	os.system('apt-get install webslayer')
	print ('###### Done')
	print ("###### Type 'webslayer' to start.")
	backtomenu_option()

def websploit():
	print ('\n###### Installing WebSploit')
	os.system('apt-get install websploit')
	print ('###### Done')
	print ("###### Type 'websploit' to start.")
	backtomenu_option()

def wfuzz():
	print ('\n###### Installing Wfuzz')
	os.system('apt-get install wfuzz')
	print ('###### Done')
	print ("###### Type 'wfuzz' to start.")
	backtomenu_option()

def whatweb():
	print ('\n###### Installing WhatWeb')
	os.system('apt-get install whatweb')
	print ('###### Done')
	print ("###### Type 'whatweb' to start.")
	backtomenu_option()

def wpscan():
	print ('\n###### Installing WPScan')
	os.system('apt-get install wpscan')
	print ('###### Done')
	print ("###### Type 'wpscan' to start.")
	backtomenu_option()

def xsser():
	print ('\n###### Installing XSSer')
	os.system('apt-get install xsser')
	print ('###### Done')
	print ("###### Type 'xsser' to start.")
	backtomenu_option()

def zaproxy():
	print ('\n###### Installing zaproxy')
	os.system('apt-get install zaproxy')
	print ('###### Done')
	print ("###### Type 'zaproxy' to start.")
	backtomenu_option()

def armitage():
	print ('\n###### Installing Armitage')
	os.system('apt-get install armitage')
	print ('###### Done')
	print ("###### Type 'armitage' to start.")
	backtomenu_option()

def backdoor_factory():
	print ('\n###### Installing Backdoor Factory')
	os.system('apt-get install backdoor-factory')
	print ('###### Done')
	print ("###### Type 'backdoor-factory' to start.")
	backtomenu_option()

def beef():
	print ('\n###### Installing BeEF')
	os.system('apt-get install beef')
	print ('###### Done')
	print ("###### Type 'beef' to start.")
	backtomenu_option()

def commix():
	print ('\n###### Installing Commix')
	os.system('apt-get install commix')
	print ('###### Done')
	print ("###### Type 'commix' to start.")
	backtomenu_option()

def exploitdb():
	print ('\n###### Installing exploitdb')
	os.system('apt-get install exploitdb')
	print ('###### Done')
	print ("###### Type 'exploitdb' to start.")
	backtomenu_option()

def linux_exploit_suggester():
	print ('\n###### Installing Linux Exploit Suggester')
	os.system('apt-get install linux-exploit-suggester')
	print ('###### Done')
	print ("###### Type 'linux-exploit-suggester' to start.")
	backtomenu_option()

def metasploit_framework():
	print ('\n###### Installing Metasploit Framework')
	os.system('apt-get install metasploit-framework')
	print ('###### Done')
	print ("###### Type 'msfconsole' to start.")
	backtomenu_option()

def msfpc():
	print ('\n###### Installing MSFPC')
	os.system('apt-get install msfpc')
	print ('###### Done')
	print ("###### Type 'msfpc' to start.")
	backtomenu_option()

def routersploit():
	print ('\n###### Installing RouterSploit')
	os.system('apt-get install routersploit')
	print ('###### Done')
	print ("###### Type 'routersploit' to start.")
	backtomenu_option()

def shellnoob():
	print ('\n###### Installing ShellNoob')
	os.system('apt-get install shellnoob')
	print ('###### Done')
	print ("###### Type 'shellnoob' to start.")
	backtomenu_option()

def dhcpig():
	print ('\n###### Installing DHCPig')
	os.system('apt-get install dhcpig')
	print ('###### Done')
	print ("###### Type 'dhcpig' to start.")
	backtomenu_option()

def iaxflood():
	print ('\n###### Installing iaxflood')
	os.system('apt-get install iaxflood')
	print ('###### Done')
	print ("###### Type 'iaxflood' to start.")
	backtomenu_option()

def inundator():
	print ('\n###### Installing Inundator')
	os.system('apt-get install inundator')
	print ('###### Done')
	print ("###### Type 'inundator' to start.")
	backtomenu_option()

def inviteflood():
	print ('\n###### Installing inviteflood')
	os.system('apt-get install inviteflood')
	print ('###### Done')
	print ("###### Type 'inviteflood' to start.")
	backtomenu_option()

def ipv6_toolkit():
	print ('\n###### Installing ipv6-toolkit')
	os.system('apt-get install ipv6-toolkit')
	print ('###### Done')
	print ("###### Type 'ipv6-toolkit' to start.")
	backtomenu_option()

def rtpflood():
	print ('\n###### Installing rtpflood')
	os.system('apt-get install rtpflood')
	print ('###### Done')
	print ("###### Type 'rtpflood' to start.")
	backtomenu_option()

def slowhttptest():
	print ('\n###### Installing slowhttptest')
	os.system('apt-get install slowhttptest')
	print ('###### Done')
	print ("###### Type 'slowhttptest' to start.")
	backtomenu_option()

def t50():
	print ('\n###### Installing t50')
	os.system('apt-get install t50')
	print ('###### Done')
	print ("###### Type 't50' to start.")
	backtomenu_option()

def terminater():
	print ('\n###### Installing Terminater')
	os.system('apt-get install terminater')
	print ('###### Done')
	print ("###### Type 'terminater' to start.")
	backtomenu_option()

def thc_ssl_dos():
	print ('\n###### Installing thc-ssl-dos')
	os.system('apt-get install thc-ssl-dos')
	print ('###### Done')
	print ("###### Type 'thc-ssl-dos' to start.")
	backtomenu_option()

def binwalk():
	print ('\n###### Installing Binwalk')
	os.system('apt-get install binwalk')
	print ('###### Done')
	print ("###### Type 'binwalk' to start.")
	backtomenu_option()

def bulk_extractor():
	print ('\n###### Installing bulk-extractor')
	os.system('apt-get install bulk-extractor')
	print ('###### Done')
	print ("###### Type 'bulk-extractor' to start.")
	backtomenu_option()

def capstone():
	print ('\n###### Installing Capstone')
	os.system('apt-get install capstone')
	print ('###### Done')
	print ("###### Type 'capstone' to start.")
	backtomenu_option()

def chntpw():
	print ('\n###### Installing chntpw')
	os.system('apt-get install chntpw')
	print ('###### Done')
	print ("###### Type 'chntpw' to start.")
	backtomenu_option()

def cuckoo():
	print ('\n###### Installing Cuckoo')
	os.system('apt-get install cuckoo')
	print ('###### Done')
	print ("###### Type 'cuckoo' to start.")
	backtomenu_option()

def dc3dd():
	print ('\n###### Installing dc3dd')
	os.system('apt-get install dc3dd')
	print ('###### Done')
	print ("###### Type 'dc3dd' to start.")
	backtomenu_option()

def ddrescue():
	print ('\n###### Installing ddrescue')
	os.system('apt-get install ddrescue')
	print ('###### Done')
	print ("###### Type 'ddrescue' to start.")
	backtomenu_option()

def dff():
	print ('\n###### Installing DFF')
	os.system('apt-get install dff')
	print ('###### Done')
	print ("###### Type 'dff' to start.")
	backtomenu_option()

def diStorm3():
	print ('\n###### Installing diStorm3')
	os.system('apt-get install distorm3')
	print ('###### Done')
	print ("###### Type 'distorm3' to start.")
	backtomenu_option()

def dumpzilla():
	print ('\n###### Installing Dumpzilla')
	os.system('apt-get install dumpzilla')
	print ('###### Done')
	print ("###### Type 'dumpzilla' to start.")
	backtomenu_option()

def extundelete():
	print ('\n###### Installing extundelete')
	os.system('apt-get install extundelete')
	print ('###### Done')
	print ("###### Type 'extundelete' to start.")
	backtomenu_option()

def foremost():
	print ('\n###### Installing Foremost')
	os.system('apt-get install foremost')
	print ('###### Done')
	print ("###### Type 'foremost' to start.")
	backtomenu_option()

def galleta():
	print ('\n###### Installing Galleta')
	os.system('apt-get install galleta')
	print ('###### Done')
	print ("###### Type 'galleta' to start.")
	backtomenu_option()

def guymager():
	print ('\n###### Installing Guymager')
	os.system('apt-get install guymager')
	print ('###### Done')
	print ("###### Type 'guymager' to start.")
	backtomenu_option()

def iphone_backup_analyzer():
	print ('\n###### Installing iPhone Backup Analyzer')
	os.system('apt-get install iphone-backup-analyzer')
	print ('###### Done')
	print ("###### Type 'iphone-backup-analyzer' to start.")
	backtomenu_option()

def pdf_parser():
	print ('\n###### Installing pdf-parser')
	os.system('apt-get install pdfid')
	print ('###### Done')
	print ("###### Type 'pdfid' to start.")
	backtomenu_option()

def pdgmail():
	print ('\n###### Installing pdgmail')
	os.system('apt-get install pdgmail')
	print ('###### Done')
	print ("###### Type 'pdgmail' to start.")
	backtomenu_option()

def peepdf():
	print ('\n###### Installing peepdf')
	os.system('apt-get install peepdf')
	print ('###### Done')
	print ("###### Type 'peepdf' to start.")
	backtomenu_option()

def regripper():
	print ('\n###### Installing RegRipper')
	os.system('apt-get install regripper')
	print ('###### Done')
	print ("###### Type 'regripper' to start.")
	backtomenu_option()

def volatility():
	print ('\n###### Installing Volatility')
	os.system('apt-get install volatility')
	print ('###### Done')
	print ("###### Type 'volatility' to start.")
	backtomenu_option()

def dnschef():
	print ('\n###### Installing DNSChef')
	os.system('apt-get install dnschef')
	print ('###### Done')
	print ("###### Type 'dnschef' to start.")
	backtomenu_option()

def fiked():
	print ('\n###### Installing fiked')
	os.system('apt-get install fiked')
	print ('###### Done')
	print ("###### Type 'fiked' to start.")
	backtomenu_option()

def hamster_sidejack():
	print ('\n###### Installing hamster-sidejack')
	os.system('apt-get install hamster-sidejack')
	print ('###### Done')
	print ("###### Type 'hamster' to start.")
	backtomenu_option()

def hexinject():
	print ('\n###### Installing HexInject')
	os.system('apt-get install hexinject')
	print ('###### Done')
	print ("###### Type 'hexinject' to start.")
	backtomenu_option()

def isr_evilgrade():
	print ('\n###### Installing isr-evilgrade')
	os.system('apt-get install isr-evilgrade')
	print ('###### Done')
	print ("###### Type 'evilgrade' to start.")
	backtomenu_option()

def mitmproxy():
	print ('\n###### Installing mitmproxy')
	os.system('apt-get install mitmproxy')
	print ('###### Done')
	print ("###### Type 'mitmproxy' to start.")
	backtomenu_option()

def protos_sip():
	print ('\n###### Installing protos-sip')
	os.system('apt-get install protos-sip')
	print ('###### Done')
	print ("###### Type 'protos-sip' to start.")
	backtomenu_option()

def rebind():
	print ('\n###### Installing rebind')
	os.system('apt-get install rebind')
	print ('###### Done')
	print ("###### Type 'rebind' to start.")
	backtomenu_option()

def responder():
	print ('\n###### Installing responder')
	os.system('apt-get install responder')
	print ('###### Done')
	print ("###### Type 'responder' to start.")
	backtomenu_option()

def rtpbreak():
	print ('\n###### Installing rtpbreak')
	os.system('apt-get install rtpbreak')
	print ('###### Done')
	print ("###### Type 'rtpbreak' to start.")
	backtomenu_option()

def rtpinsertsound():
	print ('\n###### Installing rtpinsertsound')
	os.system('apt-get install rtpinsertsound')
	print ('###### Done')
	print ("###### Type 'rtpinsertsound' to start.")
	backtomenu_option()

def rtpmixsound():
	print ('\n###### Installing rtpmixsound')
	os.system('apt-get install rtpmixsound')
	print ('###### Done')
	print ("###### Type 'rtpmixsound' to start.")
	backtomenu_option()

def sctpscan():
	print ('\n###### Installing sctpscan')
	os.system('apt-get install sctpscan')
	print ('###### Done')
	print ("###### Type 'sctpscan' to start.")
	backtomenu_option()

def sipp():
	print ('\n###### Installing SIPp')
	os.system('apt-get install sipp')
	print ('###### Done')
	print ("###### Type 'sipp' to start.")
	backtomenu_option()

def sipvicious():
	print ('\n###### Installing SIPVicious')
	os.system('apt-get install sipvicious')
	print ('###### Done')
	print ("###### Type 'sipvicious' to start.")
	backtomenu_option()

def sniffjoke():
	print ('\n###### Installing SniffJoke')
	os.system('apt-get install sniffjoke')
	print ('###### Done')
	print ("###### Type 'sniffjoke' to start.")
	backtomenu_option()

def voiphopper():
	print ('\n###### Installing VoIPHopper')
	os.system('apt-get install voiphopper')
	print ('###### Done')
	print ("###### Type 'voiphopper' to start.")
	backtomenu_option()

def xspy():
	print ('\n###### Installing xspy')
	os.system('apt-get install xspy')
	print ('###### Done')
	print ("###### Type 'xspy' to start.")
	backtomenu_option()

def brutespray():
	print ('\n###### Installing BruteSpray')
	os.system('apt-get install brutespray')
	print ('###### Done')
	print ("###### Type 'brutespray' to start.")
	backtomenu_option()

def cewl():
	print ('\n###### Installing CeWL')
	os.system('apt-get install cewl')
	print ('###### Done')
	print ("###### Type 'cewl' to start.")
	backtomenu_option()

def cmospwd():
	print ('\n###### Installing CmosPwd')
	os.system('apt-get install cmospwd')
	print ('###### Done')
	print ("###### Type 'cmospwd' to start.")
	backtomenu_option()

def creddump():
	print ('\n###### Installing creddump')
	os.system('apt-get install creddump')
	print ('###### Done')
	print ("###### Type 'creddump' to start.")
	backtomenu_option()

def crowbar():
	print ('\n###### Installing crowbar')
	os.system('apt-get install crowbar')
	print ('###### Done')
	print ("###### Type 'crowbar' to start.")
	backtomenu_option()

def crunch():
	print ('\n###### Installing crunch')
	os.system('apt-get install crunch')
	print ('###### Done')
	print ("###### Type 'crunch' to start.")
	backtomenu_option()

def findmyhash():
	print ('\n###### Installing findmyhash')
	os.system('apt-get install findmyhash')
	print ('###### Done')
	print ("###### Type 'findmyhash' to start.")
	backtomenu_option()

def gpp_decrypt():
	print ('\n###### Installing gpp-decrypt')
	os.system('apt-get install gpp-decrypt')
	print ('###### Done')
	print ("###### Type 'gpp-decrypt' to start.")
	backtomenu_option()

def hash_identifier():
	print ('\n###### Installing hash-identifier')
	os.system('apt-get install hash-identifier')
	print ('###### Done')
	print ("###### Type 'hash-identifier' to start.")
	backtomenu_option()

def hashcat():
	print ('\n###### Installing Hashcat')
	os.system('apt-get install hashcat')
	print ('###### Done')
	print ("###### Type 'hashcat' to start.")
	backtomenu_option()

def thc_hydra():
	print ('\n###### Installing THC-Hydra')
	os.system('apt-get install thc-hydra')
	print ('###### Done')
	print ("###### Type 'thc-hydra' to start.")
	backtomenu_option()

def john_the_ripper():
	print ('\n###### Installing John the Ripper')
	os.system('apt-get install john the ripper')
	print ('###### Done')
	print ("###### Type 'john';'mailer';'unshadow';'unique' to start.")
	backtomenu_option()

def johnny():
	print ('\n###### Installing johnny')
	os.system('apt-get install johnny')
	print ('###### Done')
	print ("###### Type 'johnny' to start.")
	backtomenu_option()

def keimpx():
	print ('\n###### Installing keimpx')
	os.system('apt-get install keimpx')
	print ('###### Done')
	print ("###### Type 'keimpx' to start.")
	backtomenu_option()

def maskprocessor():
	print ('\n###### Installing Maskprocessor')
	os.system('apt-get install maskprocessor')
	print ('###### Done')
	print ("###### Type 'maskprocessor' to start.")
	backtomenu_option()

def multiforce():
	print ('\n###### Installing multiforce')
	os.system('apt-get install multiforce')
	print ('###### Done')
	print ("###### Type 'multiforce' to start.")
	backtomenu_option()

def ncrack():
	print ('\n###### Installing Ncrack')
	os.system('apt-get install ncrack')
	print ('###### Done')
	print ("###### Type 'ncrack' to start.")
	backtomenu_option()

def oclgausscrack():
	print ('\n###### Installing oclgausscrack')
	os.system('apt-get install oclgausscrack')
	print ('###### Done')
	print ("###### Type 'oclgausscrack' to start.")
	backtomenu_option()

def ophcrack():
	print ('\n###### Installing ophcrack')
	os.system('apt-get install ophcrack')
	print ('###### Done')
	print ("###### Type 'ophcrack' to start.")
	backtomenu_option()

def pack():
	print ('\n###### Installing PACK')
	os.system('apt-get install pack')
	print ('###### Done')
	print ("###### Type 'pack' to start.")
	backtomenu_option()

def patator():
	print ('\n###### Installing patator')
	os.system('apt-get install patator')
	print ('###### Done')
	print ("###### Type 'patator' to start.")
	backtomenu_option()

def phrasendrescher():
	print ('\n###### Installing phrasendrescher')
	os.system('apt-get install phrasendrescher')
	print ('###### Done')
	print ("###### Type 'phrasendrescher' to start.")
	backtomenu_option()

def polenum():
	print ('\n###### Installing polenum')
	os.system('apt-get install polenum')
	print ('###### Done')
	print ("###### Type 'polenum' to start.")
	backtomenu_option()

def rainbowcrack():
	print ('\n###### Installing RainbowCrack')
	os.system('apt-get install rainbowcrack')
	print ('###### Done')
	print ("###### Type 'rainbowcrack' to start.")
	backtomenu_option()

def rcracki_mt():
	print ('\n###### Installing rcracki-mt')
	os.system('apt-get install rcracki-mt')
	print ('###### Done')
	print ("###### Type 'rcracki-mt' to start.")
	backtomenu_option()

def rsmangler():
	print ('\n###### Installing RSMangler')
	os.system('apt-get install rsmangler')
	print ('###### Done')
	print ("###### Type 'rsmangler' to start.")
	backtomenu_option()

def seclist():
	print ('\n###### Installing SecList')
	os.system('apt-get install seclist')
	print ('###### Done')
	print ("###### Type 'seclist' to start.")
	backtomenu_option()

def sqldict():
	print ('\n###### Installing SQLdict')
	os.system('apt-get install sqldict')
	print ('###### Done')
	print ("###### Type 'sqldict' to start.")
	backtomenu_option()

def statsprocessor():
	print ('\n###### Installing Statsprocessor')
	os.system('apt-get install statsprocessor')
	print ('###### Done')
	print ("###### Type 'statsprocessor' to start.")
	backtomenu_option()

def thc_pptp_bruter():
	print ('\n###### Installing THC-pptp-bruter')
	os.system('apt-get install thc-pptp-bruter')
	print ('###### Done')
	print ("###### Type 'thc-pptp-bruter' to start.")
	backtomenu_option()

def truecrack():
	print ('\n###### Installing TrueCrack')
	os.system('apt-get install truecrack')
	print ('###### Done')
	print ("###### Type 'truecrack' to start.")
	backtomenu_option()

def wordlists():
	print ('\n###### Installing wordlists')
	os.system('apt-get install wordlists')
	print ('###### Done')
	print ("###### Type 'wordlists' to start.")
	backtomenu_option()

def cryptcat():
	print ('\n###### Installing CryptCat')
	os.system('apt-get install cryptcat')
	print ('###### Done')
	print ("###### Type 'cryptcat' to start.")
	backtomenu_option()

def cymothoa():
	print ('\n###### Installing Cymothoa')
	os.system('apt-get install cymothoa')
	print ('###### Done')
	print ("###### Type 'cymothoa' to start.")
	backtomenu_option()

def dbd():
	print ('\n###### Installing dbd')
	os.system('apt-get install dbd')
	print ('###### Done')
	print ("###### Type 'dbd' to start.")
	backtomenu_option()

def dns2tcp():
	print ('\n###### Installing dns2tcp')
	os.system('apt-get install dns2tcp')
	print ('###### Done')
	print ("###### Type 'dns2tcp' to start.")
	backtomenu_option()

def http_tunnel():
	print ('\n###### Installing http-tunnel')
	os.system('apt-get install http-tunnel')
	print ('###### Done')
	print ("###### Type 'httptunnel_server'; 'httptunnel_client' to start.")
	backtomenu_option()

def httptunnel():
	print ('\n###### Installing HTTPTunnel')
	os.system('apt-get install httptunnel')
	print ('###### Done')
	print ("###### Type 'hts'; 'htc' to start.")
	backtomenu_option()

def intersect():
	print ('\n###### Installing Intersect')
	os.system('apt-get install intersect')
	print ('###### Done')
	print ("###### Type 'intersect' to start.")
	backtomenu_option()

def nishang():
	print ('\n###### Installing Nishang')
	os.system('apt-get install nishang')
	print ('###### Done')
	print ("###### Type 'nishang' to start.")
	backtomenu_option()

def powersploit():
	print ('\n###### Installing PowerSploit')
	os.system('apt-get install powersploit')
	print ('###### Done')
	print ("###### Type 'powersploit' to start.")
	backtomenu_option()

def pwnat():
	print ('\n###### Installing pwnat')
	os.system('apt-get install pwnat')
	print ('###### Done')
	print ("###### Type 'pwnat' to start.")
	backtomenu_option()

def ridenum():
	print ('\n###### Installing RidEnum')
	os.system('apt-get install ridenum')
	print ('###### Done')
	print ("###### Type 'ridenum' to start.")
	backtomenu_option()

def sbd():
	print ('\n###### Installing sbd')
	os.system('apt-get install sbd')
	print ('###### Done')
	print ("###### Type 'sbd' to start.")
	backtomenu_option()

def shellter():
	print ('\n###### Installing shellter')
	os.system('apt-get install shellter')
	print ('###### Done')
	print ("###### Type 'shellter' to start.")
	backtomenu_option()

def u3_pwn():
	print ('\n###### Installing U3-Pwn')
	os.system('apt-get install u3-pwn')
	print ('###### Done')
	print ("###### Type 'u3-pwn' to start.")
	backtomenu_option()

def webshells():
	print ('\n###### Installing Webshells')
	os.system('apt-get install webshells')
	print ('###### Done')
	print ("###### Type 'webshells' to start.")
	backtomenu_option()

def weevely():
	print ('\n###### Installing Weevely')
	os.system('apt-get install weevely')
	print ('###### Done')
	print ("###### Type 'weevely' to start.")
	backtomenu_option()

def winexe():
	print ('\n###### Installing Winexe')
	os.system('apt-get install winexe')
	print ('###### Done')
	print ("###### Type 'winexe' to start.")
	backtomenu_option()

def apktool():
	print ('\n###### Installing apktool')
	os.system('apt-get install apktool')
	print ('###### Done')
	print ("###### Type 'apktool' to start.")
	backtomenu_option()

def dex2jar():
	print ('\n###### Installing dex2jar')
	os.system('apt-get install dex2jar')
	print ('###### Done')
	print ("###### Type 'dex2jar' to start.")
	backtomenu_option()

def edb_debugger():
	print ('\n###### Installing edb-debugger')
	os.system('apt-get install edb-debugger')
	print ('###### Done')
	print ("###### Type 'edb' to start.")
	backtomenu_option()

def jad():
	print ('\n###### Installing jad')
	os.system('apt-get install jad')
	print ('###### Done')
	print ("###### Type 'jad' to start.")
	backtomenu_option()

def javasnoop():
	print ('\n###### Installing javasnoop')
	os.system('apt-get install javasnoop')
	print ('###### Done')
	print ("###### Type 'javasnoop' to start.")
	backtomenu_option()

def jd_gui():
	print ('\n###### Installing JD-GUI')
	os.system('apt-get install jd-gui')
	print ('###### Done')
	print ("###### Type 'jd-gui' to start.")
	backtomenu_option()

def ollydbg():
	print ('\n###### Installing OllyDbg')
	os.system('apt-get install ollydbg')
	print ('###### Done')
	print ("###### Type 'ollydbg' to start.")
	backtomenu_option()

def smali():
	print ('\n###### Installing smali')
	os.system('apt-get install smali')
	print ('###### Done')
	print ("###### Type 'smali' to start.")
	backtomenu_option()

def valgrind():
	print ('\n###### Installing Valgrind')
	os.system('apt-get install valgrind')
	print ('###### Done')
	print ("###### Type 'valgrind' to start.")
	backtomenu_option()

def yara():
	print ('\n###### Installing yara')
	os.system('apt-get install yara')
	print ('###### Done')
	print ("###### Type 'yara' to start.")
	backtomenu_option()

def cherrytree():
	print ('\n###### Installing cherrytree')
	os.system('apt-get install cherrytree')
	print ('###### Done')
	print ("###### Type 'cherrytree' to start.")
	backtomenu_option()

def dos2unix():
	print ('\n###### Installing dos2unix')
	os.system('apt-get install dos2unix')
	print ('###### Done')
	print ("###### Type 'dos2unix' to start.")
	backtomenu_option()

def dradis():
	print ('\n###### Installing Dradis')
	os.system('apt-get install dradis')
	print ('###### Done')
	print ("###### Type 'dradis' to start.")
	backtomenu_option()

def magictree():
	print ('\n###### Installing magictree')
	os.system('apt-get install magictree')
	print ('###### Done')
	print ("###### Type 'magictree' to start.")
	backtomenu_option()

def metagoofil():
	print ('\n###### Installing Metagoofil')
	os.system('apt-get install metagoofil')
	print ('###### Done')
	print ("###### Type 'metagoofil' to start.")
	backtomenu_option()

def nipper_ng():
	print ('\n###### Installing Nipper-ng')
	os.system('apt-get install nipper-ng')
	print ('###### Done')
	print ("###### Type 'nipper-ng' to start.")
	backtomenu_option()

def pipal():
	print ('\n###### Installing pipal')
	os.system('apt-get install pipal')
	print ('###### Done')
	print ("###### Type 'pipal' to start.")
	backtomenu_option()

def rdpy():
	print ('\n###### Installing RDPY')
	os.system('apt-get install rdpy')
	print ('###### Done')
	print ("###### Type 'rdpy' to start.")
	backtomenu_option()

def android_sdk():
	print ('\n###### Installing android-sdk')
	os.system('apt-get install android-sdk')
	print ('###### Done')
	print ("###### Type 'android' to start.")
	backtomenu_option()

def arduino():
	print ('\n###### Installing Arduino')
	os.system('apt-get install arduino')
	print ('###### Done')
	print ("###### Type 'arduino' to start.")
	backtomenu_option()

def sakis3g():
	print ('\n###### Installing Sakis3G')
	os.system('apt-get install sakis3g')
	print ('###### Done')
	print ("###### Type 'sakis3g' to start.")
	backtomenu_option()