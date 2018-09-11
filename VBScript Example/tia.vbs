'Threat Intelligence Aggregator API example script
'Looks up vendor and detection name to return URL if one exists in TIA database

'Copyright (c) 2017 Ryan Boyle randomrhythm@rhythmengineering.com.

'This program is free software: you can redistribute it and/or modify
'it under the terms of the GNU General Public License as published by
'the Free Software Foundation, either version 3 of the License, or
'(at your option) any later version.

'This program is distributed in the hope that it will be useful,
'but WITHOUT ANY WARRANTY; without even the implied warranty of
'MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
'GNU General Public License for more details.

'You should have received a copy of the GNU General Public License
'along with this program.  If not, see <http://www.gnu.org/licenses/>.

Const forwriting = 2
Const ForAppending = 8
Const ForReading = 1
Dim BoolEchoLog: BoolEchoLog  = false
Dim CurrentDirectory
Dim strDebugPath
Dim BoolDebugTrace: BoolDebugTrace = False
Dim tmpVendorName
Dim tmpDetectionName
Dim tmpAPIkey

Set args = Wscript.Arguments
if args.count >2 then
  if tmpVendorName = "" then tmpVendorName = args.item(0)
  if tmpDetectionName = "" then tmpDetectionName = args.item(1)
  if tmpAPIkey = "" then tmpAPIkey = args.item(2)
end if

if tmpAPIkey = "" then 
	wscript.echo "Missing parameter. Provide three parameters for tia.vbs as shown:" & vbcrlf & "cscript tia.vbs Sophos Troj/Zbot-LRN 0123456789ABCD"
	wscript.quit(2)
end if

CurrentDirectory = GetFilePath(wscript.ScriptFullName)
strDebugPath = CurrentDirectory

wscript.echo CheckTIA(tmpVendorName, tmpDetectionName, tmpAPIkey)


Function CheckTIA(strVendorName, strDetectionName, strTIAkey)
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
'threatintelligenceaggregator.org
strAVEurl = "https://threatintelligenceaggregator.org/api/v1/" & strVendorName & "/?name=" & strDetectionName '& "&ApiKey=" & strTIAkey
objHTTP.open "GET", strAVEurl
'header is preferred method for API key vs commented out query string above
objHTTP.setRequestHeader "ApiKey", strTIAkey

on error resume next
  objHTTP.send 
  if err.number <> 0 then
    logdata CurrentDirectory & "\TIA_Error.log", Date & " " & Time & " TIA lookup failed with HTTP error. - " & err.description,False 
    exit function 
  end if
on error goto 0  

strTIAresponse= objHTTP.responseText
if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", strVendorName & ":" & strDetectionName & "|" & strAVEurl & " - " & strTIAresponse,BoolEchoLog 

if strTIAresponse = "Request limit exceeded" then
	wscript.sleep 10000
	CheckTIA = CheckTIA(strVendorName, strDetectionName)
	exit function
end if

'json should contain detection name
if instr(strTIAresponse, chr(34) & "DetectionName" & Chr(34) & ":" & Chr(34)) = 0 then 
	CheckTIA = "ERROR"
	logdata CurrentDirectory & "\TIA_Error.log", Date & " " & Time & " TIA lookup for " & strVendorName & " " & strDetectionName & " failed with HTTP error. - " & objHTTP.status ,False 
	exit function
end if

'API should return a detection name if a value was provided
strReturnDN = getdata(strTIAresponse, chr(34), "DetectionName" & Chr(34) & ":" & Chr(34))
if strReturnDN = "" then 
	if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strReturnDN=" & Chr(34) & Chr(34),BoolEchoLog 
  exit function
end if

'queued entry means limited or no results
intQueue = getdata(strTIAresponse, "}", "Queue" & Chr(34) & ":")
if intQueue <> "null" then
  CheckTIA = "Q"
  if BoolDebugTrace = True and boolEnableTIAqueue = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "Detection name=" & strDetectionName & " CheckTIA=Q  lookupQueue.Count=" & lookupQueue.Count ,BoolEchoLog 
  exit function
end if

if len(strTIAresponse) > 0 then
  strReturnURL = getdata(strTIAresponse, chr(34), "URL" & Chr(34) & ":" & Chr(34))'return reference URL
  if strReturnURL <> "" then 
    CheckTIA = strReturnURL
    if BoolDebugTrace = True then logdata strDebugPath & "\VT_TIAapi" & "" & ".txt", "strReturnURL=" & strReturnURL,BoolEchoLog 
  End If
else
  'msgbox "failed lookup"
  'No lookup
  CheckTIA = ""
  logdata CurrentDirectory & "\TIA_Error.log", Date & " " & Time & " TIA lookup for " & strVendorName & " " & strDetectionName & " failed with HTTP error. - " & objHTTP.status & " " & objHTTP.responseText,False 

end if
end function

'End TIA example code and begin supporting code
function LogData(TextFileName, TextToWrite,EchoOn)
Set fsoLogData = CreateObject("Scripting.FileSystemObject")
if TextFileName = "" then
  msgbox "No file path passed to LogData"
  exit function
end if
if EchoOn = True then wscript.echo TextToWrite
  If fsoLogData.fileexists(TextFileName) = False Then
      'Creates a replacement text file 
      on error resume next
      fsoLogData.CreateTextFile TextFileName, True
      if err.number <> 0 and err.number <> 53 then 
        logdata CurrentDirectory & "\TIA_Error.log", Date & " " & Time & " Error logging to " & TextFileName & " - " & err.description,False 
        objShellComplete.popup err.number & " " & err.description & vbcrlf & TextFileName,,"Logging error", 30
        exit function
      end if
      on error goto 0
  End If
if TextFileName <> "" then
	on error resume next
	Set WriteTextFile = fsoLogData.OpenTextFile(TextFileName,ForAppending, False)
	WriteTextFile.WriteLine TextToWrite
	WriteTextFile.Close
	if err.number <> 0 then
		logdata CurrentDirectory & "\TIA_Error.log", Date & " " & Time & " Error logging to " & TextFileName & " - " & err.description,False 
		objShellComplete.popup err.number & " " & err.description & vbcrlf & TextFileName,,"Logging error", 30
	end if
  on error goto 0
end if
Set fsoLogData = Nothing
End Function


Function GetFilePath (ByVal FilePathName)
found = False
Z = 1

Do While found = False and Z < Len((FilePathName))
 Z = Z + 1
         If InStr(Right((FilePathName), Z), "\") <> 0 And found = False Then
          mytempdata = Left(FilePathName, Len(FilePathName) - Z)      
             GetFilePath = mytempdata
             found = True
        End If      
Loop
end Function


Function GetData(contents, ByVal EndOfStringChar, ByVal MatchString)
MatchStringLength = Len(MatchString)
x= instr(contents, MatchString)

  if X >0 then
    strSubContents = Mid(contents, x + MatchStringLength, len(contents) - MatchStringLength - x +1)
    if instr(strSubContents,EndOfStringChar) > 0 then
      GetData = Mid(contents, x + MatchStringLength, instr(strSubContents,EndOfStringChar) -1)
      exit function
    else
      GetData = Mid(contents, x + MatchStringLength, len(contents) -x -1)
      exit function
    end if  
  end if
GetData = ""
end Function
