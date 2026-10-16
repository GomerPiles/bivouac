$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if(Get-Service AppSandboxAgent -ErrorAction SilentlyContinue){Set-Service AppSandboxAgent -StartupType Disabled}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Name BypassNRO -Value 1 -PropertyType DWord -Force | Out-Null
