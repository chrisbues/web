---
title: "Sentinel - AAD Sign-In Logs"
tags:
- Sentinel
- Kusto
- AzureAD
---

# Fun with Sentinel
I have a bunch of these queries in my back pocket. Handy for normalizing the output of the Sign-In logs.

```kusto
let AADLogs = SigninLogs

 | where TimeGenerated >= ago(30d) and UserPrincipalName contains "@"

 | extend ClientAppUsed = iff(isempty(ClientAppUsed) == true, "Unknown", ClientAppUsed)

 | extend isLegacyAuth = case(ClientAppUsed contains "Browser", tobool("False"), ClientAppUsed contains "Mobile Apps and Desktop clients", tobool("False"), ClientAppUsed contains "Exchange ActiveSync", tobool("True"), ClientAppUsed contains "Unknown", bool(null), tobool("True"))

 | extend OperatingSystem = tostring(DeviceDetail.operatingSystem)

 | extend Browser = tostring(DeviceDetail.browser)

 | extend OperatingSystemVersion = case(OperatingSystem contains "Windows", (split(OperatingSystem, " ", 1)).[0], "")

 | extend DeviceID = tostring(DeviceDetail.deviceId)

 | extend TrustType = tostring(DeviceDetail.trustType)

 | extend Program = case(

 Browser contains "Microsoft Office", "WinOffice",

 Browser contains "MacOutlook", "MacOffice",

 Browser has_any("powerpnt", "outlook.exe", "winword", "excel", "mspub", "msaccess", "visio", "winproj"), "WinOffice", // these occasionally show up

 Browser contains "python", "Python",

 Browser contains "lync.exe", "Skype",

 Browser contains "Mobile Safari", "iOS Mail",

 ClientAppUsed contains "IMAP", "IMAP",

 "")

 | extend ProgramVersion = case(

 // Office on Windows identifies as its internal version number

 Program == "WinOffice" and Browser contains "Microsoft Office", case(

 (split(Browser, " ", 2)).[0] == "16.0", "2016+",

 (split(Browser, " ", 2)).[0] == "15.0", "2013",

 (split(Browser, " ", 2)).[0] == "14.0", "2010",

 (split(Browser, " ", 2)).[0] == "12.0", "2007",

 (split(Browser, " ", 2)).[0] == "11.0", "2003",

 ""),

 // Office on Mac identifies as its internal version number

 Program == "MacOffice" and Browser contains "MacOutlook", case(

 (split(Browser, " ", 1)).[0] startswith "16", "2019",

 (split(Browser, " ", 1)).[0] startswith "15", "2016",

 (split(Browser, " ", 1)).[0] startswith "14", "2011",

 (split(Browser, " ", 1)).[0] startswith "12", "2008",

 (split(Browser, " ", 1)).[0] startswith "11", "2004",

 ""),

 "")

 | extend errorCode = toint(Status.errorCode)

 | extend SigninStatus = case(errorCode == 0, "success",

 errorCode in ('50058', '50058','50140','51006','50059','65001','52004','50055','50144','50072','50074','16000','16001','16003','50127','50125','50129','50143','81010','81014','81012'), 'interrupt',

 "failure")

 | extend Network = tostring(parse_json(tostring(parse_json(NetworkLocationDetails)[0].networkNames))[0])

 | order by TimeGenerated desc

 | project Id, CorrelationId, Network, IPAddress, TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, TrustType, DeviceID, OperatingSystem, OperatingSystemVersion, Program, ProgramVersion, Browser, SigninStatus, ConditionalAccessStatus, AuthenticationRequirement, isLegacyAuth

;

AADLogs


```
