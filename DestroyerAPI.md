```txt
#     __  __|                        |          #
#        |  _ \   __| __ \   _ \  _` |  _ \     #
#        | (   | |    |   |  __/ (   | (   |    #
#       _|\___/ _|    .__/ \___|\__,_|\___/     #
#         Intrusion  _|  Detection System       #
```
     Torpedo v2 has now has a new API system
  that will allow users to add their own custom
   programs such as attack or scanning scripts

***How To Add Scripts To Destroyer API***

QuadTorp has an automated API dictionary which
both manages and executes custom API functions!
By modifying or adding information to this list,
users can add their own scanning functions!


**Setting Up Dictionary**

This is what the API dictionary looks like:
(All the key features you have to add are listed)

```python
class destroyer():
  
  def __init__(self, pub, local):
    self.globe = globals()
    self.system = {
    "host":pub,
    "local":local,
    "dir":"./sec/",
    "80":{ # <-- Detection Protocol
      "shellshock":{ # <-- Program/Vulnerability Name
        "program":"idsutil.shellshock", # <-- File & Function Name (files must be in './sec/')
        "exe":"function", # <-- Function
        "type":"http|80.443", # <-- Requirements to Execute (Device must be marked as HTTP and have either port 80 or 443 open [for this instance]). Further checkups can be made inside the function
        "active":True # <-- Enabled (can be disabled with 'False')
      },
      "login":{
        "program":"idsutil.login",
        "exe":"function",
        "type":"http|80.443",
        "active":False
      },
        "dos":{
          "program":"idsutil.dos",
          "exe":"function",
          "type":"http|80",
          "active":False
       },
         "https":{
           "program":"idsutil.https",
           "exe":"function",
           "type":"http|80",
           "active":True
        }
      },
    "22":{ # <-- New Detection Protocol
      "sshlogin":{
        "program":"idsutil.sshlogin",
        "exe":"function",
        "type":"vuln|22",
        "active":False
      }
    }
  }

[...]
```

**Implementing functions**

Destroyer API has some proprietary functions
which are used to get information and are
very important to know!
Important note: Globals become locals for custom
functions so they have all the information they
need!

Important Global Values:

```python
def login(info, tran): # All API functions have 'info' and 'tran' as their arguments!
	exec localize(info) # Localize is used to set locals for transfered values
	"Transfered Values List:"
	ip # Target IP
	host # Target IP
	lhost # Your LAN Addresss
	public # Your Public IP
	ports # String list of all discovered device ports (port options can be selected in arguments)
	scanports # Integer list of all discovered device ports
	site # http://<target_address>
	locals().update(tran) # This makes adds all globals to locals in this function!
	"Important Globals:"
	tracking.mdir # "./networks/public_ip/"
	tracking.public # Public IP
	tracking.autovuln(ip, "name_of_vuln_from_vuln_dictionary") # This automatically logs and sends information to the output, of what device has a detected vuln
	tracking.autosecure(ip, "name_of_vuln_from_vuln_dictionary") # This automatically logs and send information to the output, of what device has been secured
	tracking.update(ip, "statistic") # This will enter the time, statistic, and ip of a device into its corresponding file (and will not log it into the console output)
	netaddr.localhost # LAN IP
```

After you have modified the API dictionary and
have added your function into the './sec/' folder
go into QuadTorp and modify the vulns dictionary!

'vulns' dictionary:

```python
vulns = {
	"shellshock":"CVE-2014-6271",
	"login":"Default Login",
	"https":"No HTTPS"
	#vuln_name:vuln_description
}

[...]
```
