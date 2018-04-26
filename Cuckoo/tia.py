#Copyright (c) 2018 Ryan Boyle randomrhythm@rhythmengineering.com.
#All rights reserved.

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
import json
import requests
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.abstracts import Processing

class tia(Processing):
	order = 19
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
		queryStringPart = ""
		#print self.results["virustotal"]["results"]
		if "results" in self.results["virustotal"]:
			
			for entry in self.results["virustotal"]["results"]:
				if entry["sig"] != None:
				    if entry["vendor"] in dictTIA:
						queryStringPart = combineTIAresults(queryStringPart, entry["vendor"], entry["sig"])
						#print r.content
		if "ClamAV=" not in queryStringPart and self.results["target"]["file"].has_key("clamav") and self.results["target"]["file"]["clamav"]:
			queryStringPart = combineTIAresults(queryStringPart,"ClamAV",self.results["target"]["file"]["clamav"])
		if queryStringPart != "":
			response_data = tia_request(queryStringPart, key)

	
		json_object = []

		try:
			json_object = json.loads(response_data)
		except ValueError, e:
			CuckooProcessingError("TIA error processing combined JSON: " + response_data)
		#print json_object
		return json_object

def tia_request(vendorQueryString, apikey): #performs HTTP GET against TIA API and returns results
	url = "https://threatintelligenceaggregator.org/api/v1/MultipleRequests/?" + vendorQueryString 
	data = {"ApiKey": apikey}
	timeout = 60
	try:
		r = requests.get(url, params=data, verify=True, timeout=int(timeout))
		
	except requests.exceptions.RequestException as e:
		raise CuckooProcessingError("Unable to complete connection "
									"to TIA: {0}".format(e))
	return r.content

def combineTIAresults(queryStringPart, vendorname, detectionName):
	queryStringPieces = queryStringPart
	if queryStringPieces == "":
		queryStringPieces = vendorname + "=" + detectionName
	else:
		queryStringPieces = queryStringPieces + "&" + vendorname + "=" + detectionName	
	return queryStringPieces
		
def is_json(myjson):
  try:
	json_object = json.loads(myjson)
  except ValueError, e:
	return False
  return True