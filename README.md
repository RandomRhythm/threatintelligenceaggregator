Threat Intelligence Aggregator (TIA) is a web API search engine for virus detection names. The goal of the API is to provide context for the queried item such as the URL for the vendor encyclopedia write-up or the first time TIA saw the detection name. Detection names from the following vendors are supported:

•	Avira

•	Bitdefender

•	ClamAV

•	DrWeb

•	ESET

•	F-Secure

•	McAfee

•	Microsoft

•	Panda

•	Sophos

•	Symantec

•	Trend Micro

You must be issued an API key for use with this service. The API key can be passed as part of the headers in the HTTP get request or within the query string. Three values are passed to the API; the vendor name, detection name, and API key.   In the query string example below the vendor is Avira and the detection name is Worm/Conficker.gen.
Query string example:

`https://threatintelligenceaggregator.org/api/v1/Avira/?name=Worm/Conficker.gen&ApiKey=012345678ABCD`

Pass the API key as part of the query string  curl example:

`curl https://threatintelligenceaggregator.org/api/v1/sophos/?name=Troj/Zbot-LRN&ApiKey=0123456789ABCD`

Pass the API Key in header curl example:

`curl -H "ApiKey: 0123456789ABC" https://threatintelligenceaggregator.org/api/v1/sophos/?name=Troj/Zbot-LRN`

Result example from query:

`{"VendorName":"Sophos","DetectionName":"Troj/Zbot-LRN","URL":"https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Troj~Zbot-LRN/detailed-analysis.aspx","MalwareType":"trojan","RiskScore":null,"DateCreated":"2017-03-15T02:27:20","DateFirstSeen":"2017-03-14T00:00:00","DateLastSeen":null,"Removed":null,"ModifiedCount":0,"Queue":null}`

If you provide an invalid API key you will received a 401 error:

`HTTP/1.1 401 Unauthorized
<Error><Message>Authorization has been denied for this request.</Message></Error>`

If you  go over API threshold limit of 48 a minute you will receive a 402 error:

    <string>Rate limit exceeded</string>
All API provided dates are in UTC. 
