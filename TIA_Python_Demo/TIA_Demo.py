import json
import sys
import urllib.request
from urllib.request import Request, urlopen
from optparse import OptionParser

def tia_request(strVendor, strDetectionName, apikey): #performs HTTP GET against TIA API and returns results
    url = "https://threatintelligenceaggregator.org/api/v1/" + strVendor + "/?name=" + strDetectionName + "&ApiKey=" + apikey;

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
#loop through vendor detection names
for vendorname in vtresults["scans"]:
    if vendorname in dictTIA and vtresults["scans"][vendorname]["result"] != None: #if vendor supported by TIA

        detectionName = vtresults["scans"][vendorname]["result"]
        #TIA API call
        tiaResponse = tia_request(vendorname,detectionName, opts.apikey)
        #if valid json
        if is_json(tiaResponse) == True:
            tiaResults = json.loads(tiaResponse)
            for column in tiaResults:
                if headrow == "":
                    headrow = column
                else:
                    headrow = headrow + "," + column
            if tiarow == "":
                print (headrow)
            tiarow = ""
            for column in tiaResults:
                if tiarow == "":
                    tiarow = str(tiaResults[column])
                else:
                    tiarow = tiarow + "," + str(tiaResults[column])
            print (tiarow)

