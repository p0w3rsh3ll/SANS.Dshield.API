SANSDshield PowerShell Module
=============================

### SANSDshield module was designed to pull information about Microsoft Security Updates from the SANS Dshield REST API.

The SANS Dshield covers much more than Microsoft Security updates and is available at https://isc.sans.edu/api

Usage
-----

View April, 2016
```
(Get-SecondTuesday -Year 2016 -Month 04).ToString('yyyy-MM-dd') |
Get-SansMSPatchDay | Select @{l='Bulletin';e={$_.Id}},title,
 @{l='Components Affected';e={$_.affected}},
 @{l='kb';e={$_.kb -as [string]}},
 @{l='Known Exploits';e={
  switch($_.exploits) {
   'yes' { $true}
   'no'  {$false}
   default {}
  }
}},severity,clients,servers | Out-GridView -Title "April, 2016"
```

How many CVE were addressed in April, 2016
```
(Get-SecondTuesday -Year 2016 -Month 04).ToString('yyyy-MM-dd') | 

Get-SansMSPatchDay | Get-SansMSPatchCVE -Verbose | 
Select -Expand cve | 
Sort -Unique | Measure
```

How many patches were replaced/superseded in April, 2016
```
(Get-SecondTuesday -Year 2016 -Month 04).ToString('yyyy-MM-dd') |
Get-SansMSPatchDay | Get-SansMSPatchReplace | Sort -Unique | Measure
```