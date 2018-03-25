import json
import requests
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.abstracts import Processing

class tia(Processing):
	order = 14
	def run(self):
		self.key = "tia"
		if self.task["category"] != "file":
			return None
		dictTIA = {'BitDefender': None, 'TrendMicro': None, 'Symantec': None, 'F-Secure': None, 'ESET-NOD32': None, 'DrWeb': None, 'Avira': None, 'AntiVir': None, 'Microsoft': None, 'Sophos': None, 'Panda': None, 'BitDefender': None, 'McAfee': None, 'ClamAV': None}
		key = self.options.get("key", None)
		if not key:
				raise CuckooProcessingError("TIA API key not "
											"configured, skip")
		response_data = ""
		#print self.results["virustotal"]["results"]
		if "results" in self.results["virustotal"]:
			
			for entry in self.results["virustotal"]["results"]:
				tmpString = ""
				if entry["sig"] != None:
					if entry["vendor"] in dictTIA:
						#print entry["vendor"]
						r = tia_request(entry["vendor"], entry["sig"], key)
						#print r.content
						response_data = combineTIAresults(response_data, r.content)

		if self.results["target"]["file"].has_key("clamav") and self.results["target"]["file"]["clamav"]:
			r = tia_request("ClamAV",self.results["target"]["file"]["clamav"], key )

			response_data =  combineTIAresults(response_data, r.content)
		
		json_object = []
		if response_data != "":
			response_data = response_data + "]"
		try:
			json_object = json.loads(response_data)
		except ValueError, e:
			CuckooProcessingError("TIA error processing combined JSON: " + response_data)
		print json_object
		return json_object

def tia_request(strVendor, strDetectionName, apikey):
	url = "https://threatintelligenceaggregator.org/api/v1/" + strVendor + "/"
	data = {"name": strDetectionName, "ApiKey": apikey}
	timeout = 60
	try:
		r = requests.get(url, params=data, verify=True, timeout=int(timeout))
		
	except requests.exceptions.RequestException as e:
		raise CuckooProcessingError("Unable to complete connection "
									"to TIA: {0}".format(e))
	return r

def combineTIAresults(responsedata, tmpString):
	if is_json(tmpString):

		if responsedata == "":
			responsedata = "[" + tmpString
		else:
			responsedata = responsedata + "," + tmpString
	else:
		CuckooProcessingError("TIA error processing JSON: " + tmpString)		
	return responsedata
		
def is_json(myjson):
  try:
	json_object = json.loads(myjson)
  except ValueError, e:
	return False
  return True
