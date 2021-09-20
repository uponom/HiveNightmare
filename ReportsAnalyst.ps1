$ReportsPath = '\\amznfsxcsey61pp.home24.lan\share\Logs\CVE-2021-36934\'

$VSSErrorFixed = 0
[psobject[]]$Results = @()

foreach ($f in (Get-childItem -LiteralPath $ReportsPath -File)) {
    Write-Host '.' -NoNewline
    $PermOk = 'FAILED'
    $VSC = 'Unknown'
    [string[]]$text = Get-Content -LiteralPath $f.FullName -Encoding unicode
    # $text
    if (($text | ? {$_ -like "*All Ok*"})) { $PermOk = 'Ok' }
    if (($text | ? {$_ -like "*VSS Ok*"})) {
        $VSC = 'Ok' 
        if (($text | ? {$_ -like "*VSS FAILED*"})) { $VSSErrorFixed++ }
    } else {
        if (($text | ? {$_ -like "*VSS FAILED*"})) { $VSC = 'FAILED' }
    }
    $Results += New-Object –TypeName PSObject -Property ([ordered]@{
        'ComputerName' = $f.Name.Substring(0, $f.Name.IndexOf('_'))
        'Permissions'  = $PermOk
        'VSCRemoved'   = $VSC
    })
}
'='*100
$Results | sort permissions, name, VSCRemoved
$TotalWs = (Get-ADComputer -Filter {enabled -eq $true} -SearchBase 'OU=Desktops,OU=Computers,OU=HOME24,DC=HOME24,DC=LAN' | measure).Count
"Total numbers of workstations: $TotalWs"
"Reports are collected from $($Results.Count) ($([math]::Round($Results.Count/$TotalWs*1000)/10)% of all workstations):"
$FixedPerms = ($Results | ? Permissions -eq 'Ok').Count
"`t- Permissions fixed: $FixedPerms ($([math]::Round($FixedPerms*1000/$Results.Count)/10)%)"
$FixVSC = ($Results | ? VSCRemoved -eq 'Ok').Count
"`t- VSC cleaned: $FixVSC ($([math]::Round($FixVSC*1000/$Results.Count)/10)%)"
"`t- Total VSC fixed: $VSSErrorFixed"
$Results | Export-Csv -LiteralPath c:\tmp\ReportsAnalyse.csv -Encoding unicode -Force -Delimiter ','