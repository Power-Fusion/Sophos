<#

Sophos & Temp Banner Removal
Version 1.9
Power-Fusion
27/3/2015

Still to clean.
HKEY_CLASSES_ROOT\AppID\{752B5BD1-9128-47B7-9934-E6DE5C5397D0}
HKEY_CLASSES_ROOT\Sophos.WebControl
HKEY_CLASSES_ROOT\Sophos.WebControl.1
HKEY_CLASSES_ROOT\TypeLib\{5123D78B-3CEF-4748-9ABA-20B7150D69C6}
HKEY_CLASSES_ROOT\Wow6432Node\AppID\{752B5BD1-9128-47B7-9934-E6DE5C5397D0}
HKEY_CLASSES_ROOT\Wow6432Node\TypeLib\{5123D78B-3CEF-4748-9ABA-20B7150D69C6}
#>
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "Restart this script as Administrator!"
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    Break
}
if(get-service Sophos*){
    Write-Output 'Stopping Services'
    Stop-Service "Sophos*" -ErrorAction SilentlyContinue | Set-Service -StartupType "Disabled" -ErrorAction SilentlyContinue
    Stop-Service "Sophos Agent" -ErrorAction SilentlyContinue | Set-Service -StartupType "Disabled" -ErrorAction SilentlyContinue
    Stop-Service "Sophos Anti-Virus" -ErrorAction SilentlyContinue | Set-Service -StartupType "Disabled" -ErrorAction SilentlyContinue
    Stop-Service "Sophos Anti-Virus status reporter" -ErrorAction SilentlyContinue | Set-Service -StartupType "Disabled" -ErrorAction SilentlyContinue
    Write-Output 'Services Stopped'
}

Stop-Process -name ALMon,SAVService,SAVAdminService,ALSvc,SophosBootTasks,SCFService,SCFManager,AgentAPI,Sdcservice,RouterNT,Spa,Swc_service,Swi_service,Swi_update_64,ALsvc,ALUpdate,swi_lspdiag,swi_lspdiag_64,savmain -ErrorAction SilentlyContinue -force

Write-Output 'Processes Stopped'

$startup1 = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0'
$startup2 = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0'
$text = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue
$caption = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue
$clean = Test-Path 'HKLM:\SOFTWARE\Sophos'
$clean2 = Test-Path 'HKCU:\SOFTWARE\Sophos'
$clean3 = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Management Service'
$clean4 = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Management Service'
$clean5 = Test-Path 'HKLM:\SOFTWARE\WOW6432node\sophos\'
$norun = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'

if (($text -ne $null) -and ($text.Length -ne 0)) {
    Write-Output 'Notice Found'
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue
    Write-Host 'Removed' -foregroundcolor "Green"
}
else {
    Write-Output 'Notice Clear'
}
If (($caption -ne $null) -and ($caption.Length -ne 0)) {
    Write-Output 'Caption Found'
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue
    Write-Host 'Removed' -foregroundcolor "Green"
}
else {
    Write-Output 'Caption Clear'
}
if($startup1 -eq $true) {
    Write-Output 'Startup Found [1/2]'
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0' -Recurse
    Write-Host 'Removed' -foregroundcolor "Green"
}
else {
    Write-Output 'Startup Clear [1/2]'
}
if($startup2 -eq $true) {
    Write-Output 'Startup Found [2/2]'
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0' -Recurse
    Write-Host 'Removed' -foregroundcolor "Green"
}
else {
    Write-Output 'Startup Clear [2/2]'
}
if(Test-Path "C:\Program Files (x86)\Sophos"){
    Write-Output 'Deleting Sophos'
    Remove-Item "C:\Program Files (x86)\Sophos\*" -Force -Recurse
}
if (Test-Path "C:\Program Files (x86)\Sophos") {
    Write-Output 'Sophos Folder Found'
}
else{
    Write-Output 'Sophos Folder Not Found' 'Creating Fake'
    New-Item "C:\Program Files (x86)\Sophos" -type directory
}
Try{
    takeown /a /r /d Y /f "C:\Program Files (x86)\Sophos"
    $directory = "C:\Program Files (x86)\Sophos"
    $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [system.security.accesscontrol.PropagationFlags]"None"
    $acl = Get-Acl $directory
    $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", $inherit, $propagation, "Deny")
    $accessrule2 = New-Object system.security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", $inherit, $propagation, "Deny")
    $accessrule3 = New-Object system.security.AccessControl.FileSystemAccessRule("Users", "FullControl", $inherit, $propagation, "Deny")
    $accessrule4 = New-Object system.security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", $inherit, $propagation, "Deny")
    $acl.AddAccessRule($accessrule)
    $acl.AddAccessRule($accessrule2)
    $acl.AddAccessRule($accessrule3)
    $acl.AddAccessRule($accessrule4)
    set-acl -aclobject $acl $directory
    Write-Host 'Permissions Set' -foregroundcolor "Green"
}
Catch {
    Write-Host "Permissions Denied - May already be set" -foregroundcolor "Yellow"
}
Write-Output 'Cleaning Up'
if($clean -eq $true){
    Remove-Item -Path 'HKLM:\SOFTWARE\Sophos' -Recurse
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SAVOnAccess' -Recurse
}
if($clean2 -eq $true){
    Remove-Item -Path 'HKCU:\SOFTWARE\Sophos' -Recurse
}
if($clean3 -eq $true){
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Management Service' -Recurse
}
if($clean4 -eq $true){
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Management Service' -Recurse
}
if($clean5 -eq $true){
    Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432node\sophos\' -Recurse
}
Write-Output 'Creating registry rules and restrictions'
if($norun -ne $true) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name DisallowRun -value 1 -propertyType dword  
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name DisallowRun
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -name  1 -value sophosin.exe -Type string
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -name  2 -value sopsetup.exe -Type string
    Write-Host 'Registries Created' -foregroundcolor "Green"
}
else {
    Write-Host 'Registry already exists.' -foregroundcolor "Yellow"
}
Write-Host "`nSophos should be all gone. `nA Sophos folder will remain in Program Files (x86) - Leave this."
Write-Host "It is recommended you restart your computer!`nPress any key to exit..." -foregroundcolor "Cyan"
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
stop-process -Id $PID