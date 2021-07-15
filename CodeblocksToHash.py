#Maltego Transfrom - VirusTotal Codeblock to Hash @arieljt

from MaltegoTransform import *
import requests
import json

apiurl = "https://virustotal.com/api/v3/"
apikey = ""

mt = MaltegoTransform()
mt.parseArguments(sys.argv)
code_block_id = mt.getVar('properties.BlockID').strip()


try:
	headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
	response = requests.get(apiurl + 'intelligence/search?query=code-block:' + code_block_id, headers=headers) 
	response_json = response.json()

	for item in response_json['data']:
		me = mt.addEntity("maltego.Hash", '%s' % item['attributes']['md5'].encode("ascii"))
		me.setLinkStyle(LINK_STYLE_DASHED)

except:
    mt.addUIMessage("Exception Occurred")

    
mt.returnOutput()
