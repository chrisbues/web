---
title: "Notes on System.Collections.Generic in PowerShell"
tags:
- PowerShell
template: page.html
---

For a lot of the reporting I need to do out of 365, I often end up with tons of data to parse.

There's plenty written already about the benefits of [System.Collections.Generic.List](https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1?view=net-6.0), but here's my notes.


### Determining if a item exists
Using the [Exists](https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.list-1.exists?view=net-6.0) method we can search a List of Objects for a particular value. Useful for checking if an item exists.

```powershell
# Given an Generic List of [Objects]. Perfect for API results or CSVs
$results = [System.Collections.Generic.List[pscustomobject]]::new()

...

# Look to see a value in a particular column exists.
# Exists takes a predicate as its parameter.

$results.Exists( { param($x) $x.ObjectId -eq '036dd45a-eeca-3c30-df80-08d9bd047d56'  })   
True
```

The scriptblock as the parameter is the PowerShell equivalent of C#'s
```C#
x => { ... }
```

[This page](http://reza-aghaei.com/net-action-func-delegate-lambda-expression-in-powershell/) has a wealth of examples on anonymous functions in PowerShell.