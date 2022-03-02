---
title: "Sharepoint One Time Code Access"
tags:
- Sentinel
- Kusto
- AzureAD
---

Trying to locate shares from SharePoint/One Drive to external users that result in the One Time Code instead of creating a guest account.

Need to dig around some more on if this is accurate.

```kql
OfficeActivity | where EventSource == "SharePoint"
| where Operation == "AddedToSecureLink" and TargetUserOrGroupType == "Guest"
```

