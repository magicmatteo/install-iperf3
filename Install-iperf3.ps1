$proxy = netsh winhttp show proxy
if (($proxy) | ForEach-Object {$_.Contains("Direct access")}){
    $proxy | Add-Member -Name uri -MemberType NoteProperty -Value "Direct"
    Write-Output "This script uses an HTTPS request to download iperf"
    Write-Output "Current Proxy Settings are DIRECT - If at school, please set proxy"
    Write-Output $proxy
    $userinput = Read-Host -Prompt "Press 'Y' to automatically set http proxy for Catholic VIC schools"
    if ($userinput.ToString().ToUpper() -eq 'Y'){
        & netsh --% winhttp set proxy cloudproxy.cecv.catholic.edu.au:9403 <local>
    }
}



$url = "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip"
$output = "$env:TEMP\iperf-3.1.3-win64.zip"
$installLocation = "$env:SystemDrive\iperf3"
$exeLocation = "$env:SystemDrive\iperf3\iperf3.exe"
$logloc = "$env:TEMP\iperf3-log.txt"

if (test-Path($exeLocation)){
    $userinput = Read-Host -Prompt "$exeLocation already exists - please enter Y for full reinstallation"
    if (!($userinput.ToString().ToUpper() -eq 'Y')){
        Write-Output "User returned: $userinput - Exiting."
        exit
    }
    
    Get-Process -Name *iperf* | Stop-Process
    Remove-Item $installLocation -Recurse | Out-Null
    Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq 5201 -and $_.InstanceID -ne $null} | Get-NetFirewallRule | Remove-NetFirewallRule
    Write-Output "Finished cleaning up"
}

if (!(Test-Path($logloc))){
    New-Item -Path $env:TEMP -Name "iperf3-log.txt" -ItemType File | Out-Null
}


try {
    Invoke-WebRequest -Uri $url -OutFile $output
}
catch {
    Write-Warning "Unable to download file from $url" | Out-File $logloc -Append
    Write-Warning $_ | Out-File $logloc -Append
    exit
}


if (Test-Path($output)) {
    Write-Output "$output exists - Unzipping" | Out-File $logloc -Append
    
    if (!(Test-Path($installLocation))){
        New-Item -Path $installLocation -ItemType Directory | Out-Null
    }
    try {
        Expand-Archive -Path $output -DestinationPath $installLocation -Force
        Get-ChildItem $installLocation -Include "cygwin1.dll","iperf3.exe" -Recurse | Move-item -Destination $installLocation -ErrorAction SilentlyCOntinue
        Get-ChildItem -Path $installLocation -Directory |Remove-Item -Recurse
        Remove-Item $output
    }
    catch {
        Write-Warning "An error occured while extracting and moving folders to install location" | Out-File $logloc -Append
        Write-Warning $_ | Out-File $logloc -Append
        exit
    }

    
}

if (!(Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq 5201 -and $_.InstanceID -ne $null})){
    try {
        New-NetFirewallRule -DisplayName "IPERF3 TCP 5201"  -Direction Inbound `
                                                            -LocalPort 5201 -Protocol TCP `
                                                            -Profile Any -Action Allow `
                                                            -Program "$installLocation\iperf3.exe" | Out-Null
        New-NetFirewallRule -DisplayName "IPERF3 UDP 5201"  -Direction Inbound `
                                                            -LocalPort 5201 -Protocol UDP `
                                                            -Profile Any -Action Allow `
                                                            -Program "$installLocation\iperf3.exe" | Out-Null
        Write-Output "Successfully created firewall rules for iperf"| Out-File $logloc -Append
        Write-Output "Successfully created firewall rules for iperf"
    }
    catch {
        Write-Warning "An error occured while creating firewall rules" | Out-File $logloc -Append
        Write-Warning $_ | Out-File $logloc -Append
        exit
    }
}

Write-Output "Script completed successfully"

& c:\iperf3\iperf3.exe --% --server --daemon --format Mbits

Write-Output 'Please note - only Windows Firewall rules created'
Write-Output "If 3rd party firewall installed - please create manual rule Port 5201 TCP inbound/outbound"
Write-Output "iperf3 Process now running:"
Write-Output "|---------------------------|"
Get-Process iperf3


# REwrite this in powershell
# ::
# :: Install iperf3 as Windows service
# ::
# SET iperfdir=C:\iperf3
# SET iperfprog=iperf3.exe
# SET iperflog=iperf3-server-logs.txt
# SET servicename=iperf3
# SET start=auto
# SET binpath=%iperfdir%\srvany.exe
# SET iperfoptions=--server --daemon --port 5201 --version4 --format [m] --verbose --logfile %iperfdir%\%iperflog%
# SET displayname=iPerf3 Service
# SET description=iPerf3 Service provide a possibility to test network speed
# ::
# ::
# sc.exe create %servicename% displayname= "%displayname%" start= %start% binpath= "%binpath%"
# sc description %servicename% "%description%"
# ::
# reg add HKLM\SYSTEM\CurrentControlSet\services\%servicename%\Parameters /v AppParameters /t REG_SZ /d "%iperfoptions%"
# reg add HKLM\SYSTEM\CurrentControlSet\services\%servicename%\Parameters /v Application /t REG_SZ /d "%iperfdir%\%iperfprog%" /f
# ::
# pause
# ::