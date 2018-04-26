#TIA API Example
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
    parser.add_option("-v", "--vendorname", action="store", default=None, dest="strVendorName",
                      help="Vendor name")
    parser.add_option("-d", "--detectionname", action="store", default=None, dest="strDetectionName",
                      help="Detection name")
    return parser

#dictionary of TIA supported vendors
dictTIA = {'bitdefender': None, 'trendmicro': None, 'symantec': None, 'f-secure': None, 'eset-nod32': None, 'drweb': None, 'avira': None, 'antivir': None, 'microsoft': None, 'sophos': None, 'panda': None, 'bitdefender': None, 'mcafee': None, 'clamav': None}

parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if not opts.apikey or not opts.strDetectionName or not opts.strVendorName:
  print ("Missing required parameters")
  sys.exit(-1)    
if not opts.strVendorName.lower() in dictTIA: #check if vendor is supported by TIA
    print ("Vendor not supported:" + opts.strVendorName)
    sys.exit(-1)  
headrow = ""

tiaResponse = tia_request(opts.strVendorName,opts.strDetectionName, opts.apikey) #TIA API call

if is_json(tiaResponse) == True: #if valid json  
    tiaResults = json.loads(tiaResponse) #load json
    for column in tiaResults: #loop through provided data points (key)
        if headrow == "":
            headrow = column #start header row
        else:
            headrow = headrow + "," + column #build header row
    print (headrow)
    tiarow = ""
    for column in tiaResults: #loop through json results (value)
        if tiarow == "":
            tiarow = str(tiaResults[column]) #start csv value
        else:
            tiarow = tiarow + "," + str(tiaResults[column]) #build values csv row
    print (tiarow) #output csv of values
else: #not valid json
    print (tiaResponse)
