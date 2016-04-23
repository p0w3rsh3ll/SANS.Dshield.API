Function Get-SansMSPatchDay {
<#
    .SYNOPSIS
        Get info of Microsoft Security bulletin from SANS.org

    .DESCRIPTION
        Use the SANS DShield REST API method getmspatchday to get a json based info of Microsoft Security bulletins.

    .PARAMETER Date
        Array of strings that represent a date in the following format: yyyy-MM-dd
        
    .PARAMETER KnownExploits
        Switch to filter results and display only bulletins that have known exploits.

    .EXAMPLE
        Get-SansMSPatchDay -Date '2016-01-12','2016-02-09'

    .EXAMPLE
        '2016-01-12','2016-02-09' | Get-SansMSPatchDay -KnownExploits
        
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory,ValueFromPipeline)]
    [ValidateScript({
        try {
            if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                $true
            }
        } catch {
            $false
        }
    })]
    [string[]]$Date,

    [switch]$KnownExploits
)
Begin {
}
Process {
    $Date | ForEach-Object {
        $patches = $null
        $URI = 'http://isc.sans.edu/api/getmspatchday/{0}/?json' -f $_
        try {
            $patches = (Invoke-RestMethod -Uri $URI -ErrorAction Stop).getmspatchday
        } catch {
            Write-Warning -Message "Failed to invoke REST method getmspatchday SANS API because $($_.Exception.Message)"
        }
        if ($KnownExploits) {
            $patches | Where-Object { $_.'exploits' -eq 'yes' }
        } else {
            $patches
        }
    }
}
End {}
}

Function Get-SansMSPatchReplace {
<#
    .SYNOPSIS
        Get the knowledge based articles that a Microsoft Security bulletin replaces.

    .DESCRIPTION
        Use the SANS DShield REST API method getmspatchreplaces to get a json based info about what KBs Microsoft Security bulletins supersede.

    .PARAMETER Id
        Array of security bulletin unique identifiers

    .EXAMPLE
        Get-SansMSPatchReplace -Id 'MS16-039' 

    .EXAMPLE
        'MS16-038','MS16-039' | Get-SansMSPatchReplace
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern('^(M|m)(S|s)\d{2}-\d{3}$')]
    [string[]]$Id
)
Begin {
}
Process {
    $Id | ForEach-Object {
        $URI =  'http://isc.sans.edu/api/getmspatchreplaces/{0}/?json' -f $_
        try {
            (Invoke-RestMethod -Uri $URI -ErrorAction Stop).getmspatchreplaces
        } catch {
            Write-Warning -Message "Failed to invoke REST method getmspatchreplaces SANS API because $($_.Exception.Message)"
        }
    }
}
End {}
}


Function Get-SansMSPatchCVE {
<#
    .SYNOPSIS
        Get the CVE info related to Microsoft Security bulletins.

    .DESCRIPTION
        Use the SANS DShield REST API method getmspatchcves to get a json based info about what CVEs are included in Microsoft Security bulletins.

    .PARAMETER Id
        Array of security bulletin unique identifiers

    .EXAMPLE
        Get-SansMSPatchCVE -Id 'MS16-039' 

    .EXAMPLE
        'MS16-038','MS16-039' | Get-SansMSPatchCVE
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [ValidatePattern('^(M|m)(S|s)\d{2}-\d{3}$')]
    [string[]]$Id
)
Begin {}
Process {
    $Id | ForEach-Object {
        $URI =  'http://isc.sans.edu/api/getmspatchcves/{0}/?json' -f $_
        try {
            (Invoke-RestMethod -Uri $URI -ErrorAction Stop).getmspatchcves
        } catch {
            Write-Warning -Message "Failed to invoke REST method getmspatchcves SANS API because $($_.Exception.Message)"
        }
    }
}
End {}
}

Function Get-SecondTuesday {
<#
    .SYNOPSIS
        Get the second tuesday of this month or a specific month.

    .DESCRIPTION
        Get the second tuesday of this month as a date time object.
        Without parameter, you'll get the second tuesday of the current month.

    .PARAMETER Year
        Parameter to specify another year. Without parameter, it's the current year.

    .PARAMETER Month
        Parameter to specify another month. Without parameter, it's the current month.

    .EXAMPLE
         Get-SecondTuesday

    .EXAMPLE
        Get-SecondTuesday -Year 2016 -Month 8
#>
[CmdletBinding()]
Param(
    [Parameter()]
    [ValidateRange(1,9999)]
    [int]$Year = (Get-Date).Year,

    [Parameter()]
    [ValidateRange(1,12)]
    [int]$Month = (Get-Date).Month
)
Begin {}
Process {

    # Initialize
    $count = 0
    $2ndT = Get-Date -Year $Year -Month $Month -Day 1

    # Test 1rst day of the month and increment accordingly
    if ( ($2ndT.DayOfWeek).value__ -eq 2) {
        $count++
    }
    # Iterate until we find the 2nd Tuesday
    While ($count -ne 2) {
        $2ndT = $2ndT.AddDays(1)
        if ( ($2ndT.DayOfWeek).value__ -eq 2) {
            $count++
        }
    }
    # Output our datetime object
    $2ndT
}
End {}
}