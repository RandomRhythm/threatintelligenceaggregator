#Copyright (c) 2018 Ryan Boyle randomrhythm@rhythmengineering.com.

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
import sys
import urllib.request
from urllib.request import Request, urlopen
from optparse import OptionParser

def tia_request(vendorQueryString, apikey): #performs HTTP GET against TIA API and returns results
    url = "https://threatintelligenceaggregator.org/api/v1/MultipleRequests/?" + vendorQueryString + "&ApiKey=" + apikey;

    try:
        with urllib.request.urlopen(url) as response:
            tiadata = response.read().decode()
            return tiadata
    except:
        print("Unable to complete connection to TIA")
    return ""

def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except:
        return False
    return True

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="ThreatIntelligenceAggregator API Example")
    parser.add_option("-a", "--apikey", action="store", default=None, dest="apikey",
                      help="API key for threatintelligenceaggregator.org")
    parser.add_option("-v", "--virustotalapikey", action="store", default=None, dest="vtapikey",
                      help="API key for virustotal.com")
    parser.add_option("-s", "--hash", action="store", default=None, dest="strHash",
                      help="hash value for the file that was scanned")
    return parser

#dictionary of TIA supported vendors
dictTIA = {'BitDefender': None, 'TrendMicro': None, 'Symantec': None, 'F-Secure': None, 'ESET-NOD32': None, 'DrWeb': None, 'Avira': None, 'AntiVir': None, 'Microsoft': None, 'Sophos': None, 'Panda': None, 'BitDefender': None, 'McAfee': None, 'ClamAV': None}

parser = build_cli_parser()

opts, args = parser.parse_args(sys.argv[1:])

if not opts.apikey or not opts.vtapikey or not opts.strHash:
    print ("Missing required parameters")
    sys.exit(-1)    


with urllib.request.urlopen('https://www.virustotal.com/vtapi/v2/file/report?apikey=' + opts.vtapikey + '&resource=' + opts.strHash) as url:

    vtresults = json.loads(url.read().decode())

headrow = ""
tiarow = ""
if not "scans" in vtresults:
    print("no virustotal results")
    sys.exit(-1)
queryStringPart = ""

#loop through vendor detection names
for vendorname in vtresults["scans"]:
    if vendorname in dictTIA and vtresults["scans"][vendorname]["result"] != None: #if vendor supported by TIA

        detectionName = vtresults["scans"][vendorname]["result"]
        if queryStringPart == "":
            queryStringPart = vendorname + "=" + detectionName
        else:
            queryStringPart = queryStringPart + "&" + vendorname + "=" + detectionName
if queryStringPart != "":
    #TIA API call
    tiaResponse = tia_request(queryStringPart, opts.apikey)
    #if valid json
    if is_json(tiaResponse) == True:
        boolHeaderSet = False;
        tiaResults = json.loads(tiaResponse)
        for result in tiaResults:
            for column in result:
                if boolHeaderSet == False:
                    if headrow == "":
                        headrow = column
                    else:
                        headrow = headrow + "," + column
            boolHeaderSet = True;
            if tiarow == "":
                print (headrow)
            tiarow = ""
            for column in result:
                if tiarow == "":
                    tiarow = str(result[column])
                else:
                    tiarow = tiarow + "," + str(result[column])
            print (tiarow)

