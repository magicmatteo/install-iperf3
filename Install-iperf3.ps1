param($ConfigProxy, $Silent)

if ($silent -eq "true"){
    if (!($configproxy)){
        Write-Warning "Silent deployment requires setting of configproxy argument"
        Write-Output "Use install-iperf3.ps1 -ConfigProxy <true/false> -Silent true"
        Write-Output "Exiting..."
        Exit
    }
    elseif ($ConfigProxy -eq "true") {
        & netsh --% winhttp set proxy cloudproxy.cecv.catholic.edu.au:9403 <local>
    }
}


if (!($configproxy)) {

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
}


$url = "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip"
$output = "$env:TEMP\iperf-3.1.3-win64.zip"
$sha256 = "3C3DB693C1BDCC902CA9198FC716339373658233B3392FFE3D467F7695762CD1"
$installLocation = "$env:SystemDrive\iperf3"
$exeLocation = "$env:SystemDrive\iperf3\iperf3.exe"
$logloc = "$env:TEMP\iperf3-log.txt"

## Check for install block ##
if (test-Path($exeLocation)){
    $userinput = Read-Host -Prompt "$exeLocation already exists - please enter Y for full reinstallation"
    if (!($userinput.ToString().ToUpper() -eq 'Y')){
        Write-Output "User returned: $userinput - Exiting."
        exit
    }
    
    Get-Process -Name *iperf* | Stop-Process
    Remove-Item $installLocation -Recurse | Out-Null
    Get-NetFirewallPortFilter | Where-Object {$_.LocalPort -eq 5201 -and $_.InstanceID -ne $null} | Get-NetFirewallRule | Remove-NetFirewallRule
    Unregister-ScheduledTask -TaskName "iperf3Server" -ErrorAction SilentlyContinue
    Write-Output "Finished cleaning up"
}

if (!(Test-Path($logloc))){
    New-Item -Path $env:TEMP -Name "iperf3-log.txt" -ItemType File | Out-Null
}

## Download file block ##
try {
    Invoke-WebRequest -Uri $url -OutFile $output
}
catch {
    Write-Warning "Unable to download file from $url" | Out-File $logloc -Append
    Write-Warning $_ | Out-File $logloc -Append
    exit
}

## Hash checking block ##
try {
    Write-Output "Calculating SHA256 hash of $output" | Out-File $logloc -Append
    Write-Output "Calculating SHA256 hash of $output"
    $hash = Get-FileHash -Path $output -Algorithm SHA256
    if (!($hash.hash -ne $sha256)){
        Write-Output "SUCCESS: Hash check passed" | Out-File $logloc -Append
        Write-Host "SUCCESS: Hash check passed" -ForegroundColor Green
    }
    else {
        Throw "Critical error! HASH CHECK FAILED"
    }
}
catch {
        Write-Warning $_ | Out-File $logloc -Append
        Write-Warning "Expected SHA256 = $sha256" | Out-File $logloc -Append
        Write-Warning "SHA256 produced = $($hash.hash)" | Out-File $logloc -Append
        exit
}

## Extract and move block ##
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

## Create firewall rules block ##
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

# :: Create scheduled task for iperf3

$iperflog = "$installLocation\iperf3-server-logs.txt"
$iperfoptions = "--server --daemon --port 5201 --version4 --format Mbits --verbose --logfile $iperflog"

$trigger = New-ScheduledTaskTrigger -Daily -At 01:00
$actions = @(
    New-ScheduledTaskAction -Execute "TaskKill.exe" -Argument "/IM iperf3.exe /F"
    New-ScheduledTaskAction -Execute "iperf3.exe" -Argument $iperfoptions -WorkingDirectory $installLocation
)
$description = "iperf3 server task"

$task = New-ScheduledTask -Action $actions -Trigger $trigger -Description $description

try {
    Register-ScheduledTask -TaskName "iperf3Server" -InputObject $task
}
catch {
    Write-Warning "An error occurred while trying to create the iperf scheduled task" | Out-File $logloc -Append
    Write-Warning $_ | Out-File $logloc -Append
}

Write-Output 'Please note - only Windows Firewall rules created'
Write-Output "If 3rd party firewall installed - please create manual rule Port 5201 TCP inbound/outbound"
Start-ScheduledTask -TaskName "iperf3Server"
Write-Output "iperf3 Process now running:"
Write-Output "|---------------------------|"
Get-Process iperf3