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
"Reports count: $($Results.Count)"
$FixedPerms = ($Results | ? Permissions -eq 'Ok').Count
"Permissions fixed: $FixedPerms ($($FixedPerms*100/$Results.Count)%)"
$FixVSC = ($Results | ? VSCRemoved -eq 'Ok').Count
"VSC cleaned: $FixVSC ($($FixVSC*100/$Results.Count)%)"
"Total VSC fixed: $VSSErrorFixed"
$Results | Export-Csv -LiteralPath c:\tmp\ReportsAnalyse.csv -Encoding unicode -Force -Delimiter ','