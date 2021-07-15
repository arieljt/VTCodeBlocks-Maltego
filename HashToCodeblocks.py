#Maltego Transfrom - VirusTotal Hash to Codeblocks @arieljt

from MaltegoTransform import *
import requests
import json

apiurl = "https://virustotal.com/api/v3/"
apikey = ""

mt = MaltegoTransform()
mt.parseArguments(sys.argv)
file_hash = mt.getVar('properties.hash').strip()


try:
	headers = {'x-apikey': apikey, 'Content-Type': 'application/json'}
	response = requests.get(apiurl + 'intelligence/search?query=code-similar-to:' + file_hash, headers=headers) 
	response_json = response.json()

	for item in response_json['data']:
		if item['attributes']['md5'] == file_hash:
			for block in item['context_attributes']['code_block']:
				if block['length'] >= 5: # Adjust the minimal Codeblock length requirement
					me = mt.addEntity("arieljt.VTCodeblock", '%s' % block['binary'])
					me.addAdditionalFields("properties.BlockID", "Block ID", 'false', '%s' % block['id'])
					me.addAdditionalFields("properties.BlockLength", "Block Length", 'false', '%d' % block['length'])
					me.setLinkLabel("Offset %s" % block['offset'])		
except:
    mt.addUIMessage("Exception Occurred")

    
mt.returnOutput()
