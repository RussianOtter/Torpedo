head_banner = r"""
_ __|__ __ _       _         _       _ __ __|__ _
_ __|__      _ __ //QUADRUPLE\\ __ _      __|__ _
_ __|__ __ _      \\ TORPEDO //      _ __ __|__ _
    '                                       '
-- >=_______)                       (_______=< --
  -- - >=________)             (________=< - --
-- ----- - >=________)     (________=< - ----- --
 -- - >=________)               (________=< - --

      __  __|                        |
         |  _ \   __| __ \   _ \  _` |  _ \
         | (   | |    |   |  __/ (   | (   |
        _|\___/ _|    .__/ \___|\__,_|\___/
                     _|
                  ____________-----_'-._
      (______=<    )__|__|__|__       __|
  (______=< _ __ _____________---------_______ _

"""[1:-1]
__doc__ = r"""
_ __ ___   Intrusion Detection Systems   ___ __ _
    |                  -*-                  |
    |_ __  _ -   Savage Security   - _  __ _|. ;
      |                                   |;.:';.
 ; .' |           [ Features ]            | :".;'
":'.' |                                   |;,.|.'
:;':.;|   [ IDS ]-[ SSH Access ]          | ;\|/:
';.": |     |||                           | .| |
'.|.,;|   [ Honeypot ]                    | :| |:      
:\|/; |     ||                            |  | |.
 | |. |   [ Vuln Scans ]-[ Verbose ]      | .| |
:| |: |     |    |          |             |  | |'
.| |  |   [ Alerts ]-[ Exploit ]          |  | |
 | |. |       |           |               |  \_/
'| |  |   [ Speed ]-[ Document ]          |
 | |  |                                   |
 \_/  | [ Passive ]          [ Security ] |
     _|          [   Defcon   ]           |_
_ __|__                                   __|__ _
_ __|__ _ http://paypal.me/russianotter _ __|__ _

  QuadTorp Intrusion Dection System is designed
   to effectively map and log all LAN activity
     while also verbosing and documenting
    vulnerabilities within certain devices

_ __|__ _        - Version Info -       _ __|__ _
    |                                       |

 - 6/13/17 = v1.0   - Established Detection   -
 - 6/15/17 = v1.2   - Enhanced Preformance    -
 - 7/03/17 = v1.2.3 - New Scan Types          -
 - 1/31/18 = v1.3.3 - Enhanced User Interface -
 - 2/05/18 = v1.5.5 - Code Improvements       -
 - 2/08/18 = v1.5.6 - Scan Improvements       -
 - 2/08/18 = v1.5.7 - Major Bug Fixes         -
 - 2/10/18 = v1.6.0 - Dynamic Scanning        -
 - 2/18/18 = v1.7.2 - Major Bug Fixes         -
 - 2/26/18 = v2.2.0 - Destroyer API           -
 - 3/04/18 = v2.2.5 - Major Improvements      -
 - ?/??/?? = v?.?.? - Honeypot Added          -

_ __|__ _       - Licensing Info -      _ __|__ _
    |                                       |

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
     WARRANTY OFANY KIND, EXPRESS OR IMPLIED
  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR
  PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR 
  ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
                    SOFTWARE

  Copyright (c) Savage Security Technology 2018
 Copyright (c) Quadtorp Intrusion Detection 2018

_ __|__ _                               _ __|__ _
    |                                       |"""
scan_banner = r"""
_ __|__ _          _         _          _ __|__ _
_ __|__      _ __ // TORPEDO \\ __ _      __|__ _
"""
help_info = r"""
_ __|__ _          _         _          _ __|__ _
_ __|__      _ __ // TORPEDO \\ __ _      __|__ _
_ __|__ _         \\ARGUMENTS//         _ __|__ _

:: --ttl :: Connection timeout.

:: --hd :: Hides donation information.

:: -r :: --rate :: Minutes between scans.

:: -s :: --smooth :: Smoothly print scans.

:: -m :: --maxthread :: Limits how many active
threads can be made. More threads means more CPU
usage and battery consumption! Min: 20 Max: 400

:: -a :: --auto-clear :: Clear terminal after x
amount of scans have been made. This will reduce
lag and memory buildup (especially for long-term
scans).

:: -p :: --ports :: Sets ports to scan on nodes.
Warning: If you don't include ports that are
needed for certain security scans, vulns will not
be detected.

:: -l :: --level :: Select scanning intensity
	level while searching for devices.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::SECURITY: Find vulnerable devices and report
              any new devices on the network.
..::PASSIVE : Scan basic devices and log info.
..::DEFCON  : Report vulnerable devices and
              actively check for network ports.

:: -n :: --network-level :: Scanning Range.
- --- ----  -  ---- +[ OPT ]+ ----  -  ---- --- -
..::DYNAMIC : Scans all subnet ranges and reports
              all active subnets for future scans
..::LOCAL   : Scans all addresses on the same
              level as the host scanning.
..::MAX     : Scans all addresses.

- --- ----  -  ---- +[ TIP ]+ ----  -  ---- --- -
1. Try to avoid stopping the program while a scan
is actively running. This may lead to large scale
crashes, so instead stop the program when it is
either printing statistics or when it is waiting
to initialize the next scan.

2. To set up custom subnet scan ranges, go to
./networks/<network>/stat.dyn (or make stat.dyn)
and make a Python list containing the first 3
positions of the address followed by %s. When
set in dynamic mode, QuadTorp will use this file
to know where to scan! If you don't know your
active address range, run QuadTorp in max mode.
Example of stat.dyn:
  ["192.168.1.%s","192.168.2.%s","192.168.3.%s"]

3. Customize your attacks and scans in the 
destroyer API file! Disabling ports will limit
scan types. 
"""[1:]

agreement = """
   By entering 'y' you agree to the licensing 
 agreement and will uphold to copyright holders
       as the creators of this software.
     Acknowledge Terms & Conditions [y/n]"""

import socket, time, sys, argparse, threading, Queue, logging, random, paramiko, os, requests, string, SocketServer
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if sys.platform == "ios":
	import console
	console.set_font("Menlo",12.1)
if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
	print help_info
	sys.exit()
vulns = {
	"shellshock":"CVE-2014-6271",
	"login":"Default Login",
	"https":"No HTTPS"
}
secauth = "DEADBEEF"

parser = argparse.ArgumentParser()
parser.add_argument("-l","--level",
	help="Scanning Intensity. Default: %(default)s",
	default="passive",
	choices=["passive", "security", "defcon"])
parser.add_argument("-n","--network-level",
	help="LAN IP Range. Default: %(default)s",
	default="local",
	choices=["local","dynamic","max"])
parser.add_argument("-v","--verbose",
	help="Document Advanced Findings. Default: %(default)s",
	default=False,
	action="store_true")
parser.add_argument("-r","--rate",
	help="Set time between scans (minutes). Default: %(default)s",
	type=float, default=15)
parser.add_argument("-s","--smooth",
	help="Smoothing printing. Default: %(default)s",
	default=False,
	action="store_true")
parser.add_argument("-m","--maxthread",
	help="Set max amount of threads allowed to run. Default: %(default)s",
	type=int, default=130,
	choices=list(range(20,401)))
parser.add_argument("-a","--auto-clear",
	help="Set amount of scans before terminal clear. Default: %(default)s",
	type=int, default=False,
	choices=list(range(1,101)))
parser.add_argument("--ttl",
	help="Connection Timeout. Default: %(default)s",
	type=int, default=5)
parser.add_argument("-p","--ports",
	help="Ports Torpedo Scans. Default %(default)s",
	type=eval,
	default=[21,22,25,53,80,145,2000,
	8080,443,8080]+list(range(137,140)))
args = parser.parse_args()
if type(args.ports) != list:
	args.ports = [21,22,25,53,80,145,2000,
	8080,443,8080]+list(range(137,140))
socket.setdefaulttimeout(args.ttl)

if "recent.md" not in os.listdir("./"):
	args.network_level = "local"
	args.level = "passive"
	args.ports = [80,443]
	args.ttl = 8
	args.smooth = True
	args.rate = 1

class destroyer():
	
	def __init__(self, pub, local):
		self.globe = globals()
		self.system = {
			"host":pub,
			"local":local,
			"dir":"./sec/",
			"80":{
					"shellshock":{
						"program":"idsutil.shellshock",
						"exe":"function",
						"type":"http|80.443",
						"active":False
					},
					"login":{
						"program":"idsutil.login",
						"exe":"function",
						"type":"http|80.443",
						"active":False # Example
					},
					"dos":{
						"program":"idsutil.dos",
						"exe":"function",
						"type":"http|80",
						"active":False # Example
					},
					"https":{
						"program":"idsutil.https",
						"exe":"function",
						"type":"http|80",
						"active":True
					}
				},
			"22":{
				"sshlogin":{
					"program":"idsutil.sshlogin",
					"exe":"function",
					"type":"vuln|22",
					"active":False # Example
					}
				}
		}
	
	def torp(self, proto, program, info):
		proto = str(proto)
		_exe = self.system[proto][program]["exe"]
		_pro = self.system[proto][program]
		if _exe == "program":
			pass
		if _exe == "function":
			exec "from sec."+_pro["program"].split(".")[0] + " import "+_pro["program"].split(".")[1]
			exec _pro["program"].split(".")[1]+"(info,self.globe)"
	
	def initialize(self, ip, proto, dtype, info):
		for pro in self.system[str(proto)]:
			if dtype.lower() in self.system[str(proto)][pro]["type"].split("|")[0]:
				for p in info["ports"].split("."):
					if p in self.system[str(proto)][pro]["type"].split("|")[1]:
						if self.system[str(proto)][pro]["active"] is True:
							self.torp(proto, pro, info)

class TCPListen(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(1024).strip()
		if secauth in data:
			del data
			if [self.client_address[0],"shellshock"] not in _vdevices:
				_vdevices.append([self.client_address[0], "shellshock"])
		self.request.sendall("Done.")
	def log_message(self, format, *args):
		return 

def start_server(lhost):
	globals()["_servport"] = 11337
	for _ in range(5):
		try:
			serv = SocketServer.TCPServer((lhost, _servport), TCPListen)
			serv.allow_reuse_address = True
			try:
				serv.serve_forever()
			except:
				serv.server_close()
				break
		except Exception as e:
			pass
		globals()["_servport"] += _

def start_listen(lhost):
	if "ss_http" not in threading._active:
		t = threading.Thread(target=start_server, args=(lhost,))
		t.name = "ss_http"
		t.daemon = True
		t.start()

def loading(rate=0.0007, length=15, msg="", bmsg="", percent=True, amsg="", asyn=False):
	lchr = u"\u2588"
	if len(msg) > 0:
		print msg
	for _ in range(101):
		a = int((_/1000.0)*int(str(length)+"0"))
		p = length-a
		if asyn:
			msg = bmsg + (lchr*a)+(" "*p)+asyn
		else:
			msg = bmsg + (lchr*a)+(" "*p)+" %s"+amsg
		if percent:
			_ = str(_)
		else:
			_ = ""
		if len(str(_)) == 2:
			_ = "0"+str(_)
		elif len(str(_)) == 1:
			_ = "00"+str(_)
		sys.stdout.write("\r"+msg%_)
		time.sleep(rate)
		if random.randint(0,17) == 1:
			time.sleep(rate*random.randint(8,10))
	time.sleep(rate*50)
	print
	return 

class Timer():
	def __init__(self):
		self.start = time.time()
	
	def restart(self):
		self.start = time.time()
	
	def time(self):
		end = time.time()
		m, s = divmod(end - self.start, 60)
		h, m = divmod(m, 60)
		time_str = "%02d:%02d:%02d" % (h, m, s)
		print "\r..:  Time Elapse  :.." + (" "*9) + "..: 00:%s :.."%time_str

def getauth():
	globals()["_vdevices"] = []
	globals()["secauth"] = "".join(random.sample(string.hexdigits.upper()*10,6))
	return secauth

class radar():
	
	def __init__(self):
		complt = False
		for ipget in ["http://ip.42.pl/raw", "http://ipecho.net/plain?"]:
			try:
				self.public = requests.get(ipget, timeout=args.ttl).content
				if len(self.public) < 16:
					complt = True
					break
			except:
				pass
		if not complt:
			self.public = "0.0.0.0"
			print "..: Network :.."+" "*19+"..: OFFLINE :.."
		if self.public not in os.listdir("./networks"):
			os.mkdir("./networks/"+self.public)
			f = open("./networks/"+self.public+"/__init__.py","w")
			f.write(" ")
			f.close()
		self.mdir = "./networks/"+self.public+"/"
	
	def offline(self, ip):
		ip = ip.replace(" ","")
		f = open(self.mdir+ip+".md","a")
		f.write("[%s][%s] *[ Unactive ]*\n"%(ip, time.strftime("%X %x")))
		f.close()
	
	def vuln(self, ip, vuln):
		ip = ip.replace(" ","")
		f = open(self.mdir+ip+".md","a")
		f.write(vuln+"\n")
		f.close()
	
	def autovuln(self, ip, vuln):
		ip = ip.replace(" ","")
		warn = "\r"+_ipdb[ip]+"|"
		vwarn = vulns[vuln]
		pad = (11-len(vwarn))/2.0
		if pad > 1:
			pad = [int(pad),int(round(pad))]
		else:
			pad = [1,1]
		vwarn = (" "*pad[0])+vwarn+(" "*pad[1])
		pad = (17-len(ip))/2.0
		ip2 = (" "*int(pad))+ip+(" "*int(round(pad)))
		pad = [pad,pad]
		out = warn+vwarn+"["+ip2+"]"+"[{0} VULN {0}]"
		b = 0
		out2 = ""
		while len(out2) < 49:
			out2 = out.format(" "*b)
			b += 1
		q.put(["warn",out2])
		if ip+".md" not in os.listdir(self.mdir):
			f = open(self.mdir+ip+".md","a")
			f.close()
		st = open(self.mdir+ip+".md").read().count(vulns[vuln])/2.0
		if st.is_integer() == True and st != 0.0:
			self.vuln(ip,"[%s][%s] *[Vulnerable]*\n***Host is vulnerable to %s***" %(time.strftime("%X %x"), ip, vulns[vuln]))
			return True
		stattrack.vuln += 1
		return False
	
	def secured(self, ip, vuln):
		ip = ip.replace(" ","")
		f = open(self.mdir+ip+".md","a")
		f.write(vuln+"\n")
		f.close()
	
	def autosecure(self, ip, vuln):
		ip = ip.replace(" ","")
		warn = "\r"+_ipdb[ip]+"|"
		vwarn = vulns[vuln]
		pad = (11-len(vwarn))/2.0
		if pad > 1:
			pad = [int(pad),int(round(pad))]
		else:
			pad = [1,1]
		vwarn = (" "*pad[0])+vwarn+(" "*pad[1])
		pad = (17-len(ip))/2.0
		ip2 = (" "*int(pad))+ip+(" "*int(round(pad)))
		pad = [pad,pad]
		out = warn+vwarn+"["+ip2+"]"+"[{0}SECURE{0}]"
		b = 0
		out2 = ""
		while len(out2) < 49:
			out2 = out.format(" "*b)
			b += 1
		if ip+".md" in os.listdir(self.mdir):
			q.put(["warn",out2,""])
			st = open(self.mdir+ip+".md").read().count(vulns[vuln])/2.0
			if st.is_integer() == False and st != 0.0:
				self.secured(ip,"[%s][%s] *[  Secure  ]*\n***Host has patched %s***" %(time.strftime("%X %x"),ip,vulns[vuln]))
	
	def update(self, address, stat="Online"):
		ip = address
		path = self.mdir
		if ip+".md" not in os.listdir(path):
			globals()["_firstscan"] = True
			f = open(path+ip+".md","w")
			f.write("[%s][%s] *[Discovered]*\n"%(ip, time.strftime("%X %x")))
			if stat == "JOINED":
				f.write("**Note: Device Not From Orginal Network**\n")
			f.close()
		else:
			globals()["_firstscan"] = False
			if args.level == "defcon":
				try:
					ports = portscan(address)
				except:
					ports = []
				if len(ports) > 0:
					np = []
					for _ in ports:
						np.append(str(_))
					ports = np
					del np
					f = open(path+ip+".md","a")
					f.write("[%s][ %s ]\n"%(time.strftime("%X %x")," ".join(ports)))
					f.close()
			f = open(path+ip+".md","a")
			f.write("[%s][%s] *[  %s  ]*\n"%(ip, time.strftime("%X %x"),stat))
			f.close()

def startup():
	print scan_banner
	sys.stdout.write("///Network Scanning Protocol")
	sys.stdout.write(" "*(21-(len(args.level)+8)))
	sys.stdout.write("..: %s :..\n"%args.level.upper())
	time.sleep(0.5)
	if args.level == "defcon":
		print "..: Mapping Technique :.." + (" "*8) + "..:  %s :.."%"THREAD"
	else:
		print "..: Mapping Technique :.." + (" "*10) + "..: %s :.."%"THREAD"
	print "..: Networking Levels :.." + (" "*(16-len(args.network_level))) + "..: %s :.."%args.network_level.upper()
	time.sleep(0.1)
	print "..: Network ID :.." + (" "*20) + "..: N01 :.."
	time.sleep(1)
	loads = [
		"Initializing Network",
		"Loading Regulatory",
		"Activating",
		"IDS"
		]
	for _ in loads:
		loading(0.005, bmsg="..: %s :.. "%_, percent=True, length=28-(len(_)), asyn=" ..: %s :..")
		time.sleep(0.1)
	del loads

def print_session():
	print
	sys.stdout.write("///Regulatory Scan Initiated")
	sys.stdout.write(" "*(21-(len(args.level)+8)))
	sys.stdout.write("..: %s :..\n"%args.level.upper())
	time.sleep(0.5)
	loads = [
		"Initializing Scan"
	]
	for _ in loads:
		loading(0.001, bmsg="..: %s :.. "%_, percent=True, length=28-(len(_)), asyn=" ..: %s :..")
		time.sleep(0.1)
	scanid = str(stattrack.scanid)
	while len(scanid) < 3:
		scanid = "0"+scanid
	print "..: Scan Identification :.."+(" "*11)+"..: %s :.." %scanid
	getauth()
	print "..: Security Auth :.."+(" "*14)+"..: %s :.."%secauth
	nl = netaddr.localhost
	print "..: Local Address :.."+(" "*(20-len(nl)))+"..: "+nl+" :.."
	if args.verbose:
		avde = len(os.listdir(tracking.mdir))-1
		minpd = 24.0*60.0
		Spd = minpd/args.rate
		spd = (((Spd*66.0)/1000.0)/1000.0)*avde
		sph = (spd/24.0)*1000.0
		spd = eval(str(spd)[:6])
		sph = eval(str(sph)[:6])
		Spd = int(Spd)
		Spd = eval(str(Spd)[:6])
		if spd <= 0.0:
			spd = "N/A"
			sph = "N/A"
		print "..: Scans Per Day :.."+(" "*(20-len(str(Spd))))+"..: "+str(Spd)+" :.."
		print "..: Storage Per Day :.."+(" "*(15-len(str(spd))))+"..: "+str(spd)+" MB :.."
		print "..: Storage Per Hour :.."+(" "*(14-len(str(sph))))+"..: "+str(sph)+" KB :.."
		time.sleep(2)
	time.sleep(3)
	if "--hd" not in sys.argv:
		if sys.platform == "ios":
			print "..: Donate :.."," "*20,
			sys.stdout.write("..: ")
			console.write_link("PayPal","https://paypal.me/russianotter")
			sys.stdout.write(" :..")
			print
		else:
			print "..: Donate :.."," "*3,"https://paypal.me/russianotter"
	print "_"*6,"_"*41

def makesock(opt=1):
	try:
		if opt == 1:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			s.settimeout(args.ttl)
		if opt == 2:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(args.ttl)
		return s
	except:
		pass

def connsock():
	s = socket.create_connection
	return s

def sshsock():
	try:
		c = paramiko.SSHClient()
		c.load_system_host_keys()
		c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		return c
	except:
		pass

def auto_update(ip, nid="", stat="", t="ACTIVE"):
	if stat == "on":
		if ip+".md" not in os.listdir(tracking.mdir) and globals()["_firstscan"] == False:
			if args.level in ["security","defcon"]:
				q.put(["ip",nid,ip,"JOINED","alert"])
				tracking.update(ip,"JOINED")
				stattrack.new += 1
			else:
				q.put(["ip",nid,ip,"JOINED"])
				tracking.update(ip,"JOINED")
				stattrack.new += 1
		else:
			q.put(["ip",nid,ip,t])
			tracking.update(ip)
			stattrack.online += 1
	if stat == "off":
		if ip+".md" in os.listdir(tracking.mdir):
			stattrack.offline += 1
			q.put(["ip",nid,ip,"UNACTIVE"])
			tracking.offline(ip)

class hexit():
	def next(self, pre="N"):
		p = hex(self.i)[2:].zfill(len(str(self.i)))
		while len(p) < 5:
			p = "0"+p
		p = pre+p
		self.i += 1
		return p.upper()
		
	def __init__(self,start=1):
		self.i = start
	
	def reset(self):
		self.i = 0

class addressing():
	
	def __init__(self, netlvl=args.network_level):
		self.nlocal = 1
		self.ndyn = 0,1
		self.nmax = [1,1,1]
		try:
			s = makesock()
			s.settimeout(5)
			s.connect(("8.8.8.8", 53))
			self.localhost = s.getsockname()[0]
			s.close()
		except:
			self.localhost = "0.0.0.0"
		self.blocal = ".".join(self.localhost.split(".")[:3])+".x"
		self.bmax = ".".join(self.localhost.split(".")[:1]) + ".%d.%d.%d"
		if tracking.public not in os.listdir("./networks"):
			globals()["_firstscan"] = True
		else:
			globals()["_firstscan"] = False
		if args.network_level == "dynamic":
			path = "./networks/"+tracking.public+"/"
			if "stat.dyn" not in os.listdir(path) and len(os.listdir(path)) > 2:
				dyn = []
				for _ in os.listdir(path):
					if _.count(".") > 3:
						net = _[:-3].split(".")
						net = ".".join(net[:3])+".%s"
						dyn.append(net)
				ndyn = []
				for _ in dyn:
					if _ not in ndyn:
						ndyn.append(_)
				f = open(path+"stat.dyn","w")
				f.write(str(ndyn))
				f.close()
				self.bdyn = ndyn
			elif len(os.listdir(path)) > 2:
				self.bdyn = eval(open(path+"stat.dyn").read())
			else:
				print "..: Notice :.. Max level scan is required before\ndynamic scanning can be activated!"
				print "..: Level Switched :.."+(" "*14)+"..:  MAX  :.."
				args.network_level = "max"
	
	def next_local(self):
		if self.nlocal == 255:
			return False
		address = self.blocal.replace("x", str(self.nlocal))
		self.nlocal += 1
		return address
	
	def next_max(self):
		if self.nmax.count(255) == 3:
			return False
		if self.nmax[1] == 255:
			self.nmax[0:] = self.nmax[0]+1,1,1
		if self.nmax[2] == 255:
			self.nmax[1:] = self.nmax[1]+1,1
		address = self.bmax%tuple(self.nmax)
		self.nmax[2] += 1
		return address
	
	def next_dyn(self):
		try:
			if self.ndyn[1] > 254:
				self.ndyn = self.ndyn[0]+1,0
			if self.ndyn[0] > len(self.bdyn):
				return False
			address = self.bdyn[self.ndyn[0]] % self.ndyn[1]
			self.ndyn = self.ndyn[0],self.ndyn[1]+1
			return address
		except:
			return False

def portdetect(ip, port):
	s = makesock(2)
	s.settimeout(2)
	try:
		v = s.connect_ex((ip,port))
		if v == 0:
			return port
		else:
			return False
	except:
		return False

def portscan(ip, rng=False):
	if not rng:
		rng = args.ports
	ports = []
	for _ in rng:
		p = portdetect(ip,_)
		if p:
			ports.append(p)
	return ports

class statistics():
	
	def __init__(self, network):
		self.network = network
		self.totalnodes = 0
		self.online = 0
		self.offline = 0
		self.new = 0
		self.vuln = 0
		self.scanid = 0
	
	def autoout(self, val):
		val = str(val)
		sys.stdout.write("..: ")
		dist = 11-len(val)
		for _ in range(dist):
			sys.stdout.write("-")
			time.sleep(0.05)
		for _ in str(val):
			sys.stdout.write(_)
			time.sleep(0.1)
		sys.stdout.write(" :..\r\n")
		
	def print_st(self):
		time.sleep(args.ttl)
		print
		print "///Scan Report Diagnostics    ..: Data Logged :.."
		print "\r..:  IPs Scanned  :.."+(" "*9),
		self.autoout(self.totalnodes)
		print "\r..: Vulnerable IP :.."+(" "*9),
		self.autoout(self.vuln)
		print "\r..:  New Devices  :.."+(" "*9),
		self.autoout(self.new)
		print "\r..:  Offline IPs  :.."+(" "*9),
		self.autoout(self.offline)
		print "\r..:  Active Addr  :.."+(" "*9),
		self.autoout(self.online)
		if args.verbose:
			timekeeper.time()
		print
	
	def reset(self):
		self.totalnodes = 0
		self.online = 0
		self.offline = 0
		self.vuln = 0
		self.new = 0

def _drone():
	try:
		while True:
			data = q.get()
			if data == "exit":
				break
			if data[0] == "warn":
				if data[1] not in _dontreport:
					_dontreport.append(data[1])
					if len(data) == 3:
						print "\r"+data[1]
					else:
						logging.warning("\r"+data[1])
			if data[0] == "ip":
				pad = (17-len(data[2]))/2
				pad = [pad,pad]
				if pad[0]+pad[1]+len(data[2]) != 17:
					pad = pad[0],pad[0]+1
				out = data[1]+"|"+(" ."*5)+" ["+" "*pad[0] + data[2] + " "*pad[1]+"]"
				pad = (10-len(data[3]))/2
				out += "["+(" "*pad)+data[3]+(" "*pad)+"]"
				if "alert" in data:
					logging.warning("\r"+out)
					if args.smooth:
						time.sleep(0.01)
				else:
					print out
					if args.smooth:
						time.sleep(0.01)
			q.task_done()
	except:
		pass

def _daemonizer():
	try:
		while True:
			if "stopped" in str(threading._active):
				nl = {}
				for _ in threading._active:
					if "stopped" not in threading._active[_]:
						nl.update({_:threading._active[_]})
				threading._active = nl
	except:
		pass

def vulnlog():
	try:
		while True:
			while _inprog is False:
				pass
			try:
				if len(_vdevices) > 0:
					for _ in _vdevices:
						if True:#_[0] != netaddr.localhost:
							tracking.autovuln(_[0],_[1])
							_vdevices.pop(_vdevices.index(_))
			except Exception as e:
				break
	except:
		pass

def start_loggers(bots=1):
	if "_daemonizer" not in str(threading._active):
		t = threading.Thread(target=_daemonizer)
		t.daemon = True
		t.name = "_daemonizer"
		t.start()
	if "_msgrdrone" not in str(threading._active):
		t = threading.Thread(target=_drone)
		t.daemon = True
		t.name = "_msgrdrone"
		t.start()
	if "_vulnlog" not in str(threading._active):
		t = threading.Thread(target=vulnlog)
		t.daemon = True
		t.name = "_vulnlog"
		t.start()

def vulncheck(ip, scanports, state, nid):
	info = {
		"ip":ip,
		"host":ip,
		"lhost":netaddr.localhost,
		"public":destroyer.system["host"],
		"rhost":ip,
		"ports":".".join(str(p) for p in scanports),
		"scanports":scanports,
		"site":"http://"+ip
	}
	for _ in scanports:
		if str(_) in destroyer.system:
			destroyer.initialize(ip, str(_), state.lower(), info)
	state = state.upper()
	if ip not in _dontreport:
		if state == "ACTIVE":
			auto_update(ip,nid,"on")
		elif state == "HTTP":
			dor = True
			for da in _dontreport:
				if ip in da and vulns["https"] in da:
					dor = False
			if dor:
				auto_update(ip,nid,"on",t=state)
		elif state == "UNACTIVE":
			auto_update(ip,nid, stat="off",t=state)
		elif len(state) > 1:
			q.put(["ip",nid,ip,state,"alert"])

def check_node(ip, nid, lvl=args.level):
	try:
		stattrack.totalnodes += 1
		if lvl == "passive":
			try:
				pt,pro = 1,"ACTIVE"
				if args.verbose:
					pt,pro = 80,"HTTP"
				s = connsock()
				s((ip,pt))
				auto_update(ip,nid,"on",t=pro)
				return True
			except socket.error as e:
				if e.errno == 61:
					auto_update(ip,nid,"on")
					return True
				elif e.message == "timed out":
					auto_update(ip,nid, stat="off",t="UNACTIVE")
				else:
					return False
			except:
				return False
		
		if lvl in ["defcon","security"]:
			try:
				scanports = portscan(ip,args.ports)
			except:
				scanports = []
			state = ""
			try:
				s = connsock()
				s((ip,80))
				state = "HTTP"
			except socket.error as e:
				if e.errno == 61:
					state = "ACTIVE"
				elif e.message == "timed out":
					state = "UNACTIVE"
			except Exception as e:
				pass
			t = threading.Thread(target=vulncheck, args=(ip, scanports, state, nid,))
			t.daemon = True
			t.start()
	except Exception as e:
		pass

def scan(setting=args.level):
	if tracking.public == "0.0.0.0":
		q.put(["ip"," wan0 ","OFFLINE","WIFI"])
	while 1:
		while threading.active_count() > args.maxthread:
			pass
		if args.network_level == "local":
			ip = netaddr.next_local()
		elif args.network_level == "max":
			ip = netaddr.next_max()
		elif args.network_level == "dynamic":
			ip = netaddr.next_dyn()
		nid = ip_count.next()
		if ip == False:
			break
		_ipdb.update({ip:nid})
		t = threading.Thread(target=check_node, args=(ip,nid,))
		t.daemon = True
		t.start()
		if args.smooth:
			time.sleep(0.005)
	q.join()

def toggle():
	globals()["_inprog"] = not _inprog

try:
	if __name__ == "__main__":
		globals()["_vdevices"] = []
		globals()["_inprog"] = False
		q = Queue.Queue()
		tracking = radar()
		netaddr = addressing()
		globals()["destroyer"] = destroyer(tracking.public, netaddr.localhost)
		start_listen(netaddr.localhost)
		print head_banner
		if "recent.md" not in os.listdir("./"):
			print __doc__
			print agreement.upper(),
			if raw_input().lower() == "y":
				print "\n  Thank you acknowlging the terms & conditions".upper()
				rcf = open("recent.md","w")
				rcf.write(" ")
				rcf.close()
				print """
	_ __|__ _                               _ __|__ _
	    |                                       |"""
			else:
				print "\n               Please acknowledge\n      the terms & conditions before running".upper()
				print """
	_ __|__ _                               _ __|__ _
	    |                                       |"""
				sys.exit(0)
		socket.setdefaulttimeout(args.ttl)
		startup()
		timekeeper = Timer()
		stattrack = statistics(netaddr.localhost)
		for _ in range(2):
			start_loggers()
		threadnote = threading.active_count()+3
		while True:
			for _ in range(q.qsize()):
				q.get()
				del x
			globals()["_dontreport"] = []
			globals()["_ipdb"] = {}
			netaddr = addressing()
			stattrack.scanid += 1
			if args.auto_clear:
				if stattrack.scanid > args.auto_clear:
					if sys.platform == "ios":
						console.clear()
					else:
						os.system("clear")
			ip_count = hexit()
			print_session()
			if args.verbose:
				timekeeper.restart()
			toggle()
			scan()
			while threading.active_count() > threadnote:
				time.sleep(0.5)
			toggle()
			stattrack.print_st()
			stattrack.reset()
			end = time.time()+(60*args.rate)
			while time.time() < end:
				try:
					pass
				except:
					print "..: Scanning Successfully Stopped :.."
					q.put("exit")
					sys.exit(0)
		print "..: Scanning Successfully Stopped :.."
		q.put("exit")
		sys.exit(0)
except:
	q.put("exit")
	sys.exit(0)
