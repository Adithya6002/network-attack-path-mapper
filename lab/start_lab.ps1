# Starts the 4 lab VMs safely, one at a time, after checking free memory.
# Usage (PowerShell, from the project folder):  .\lab\start_lab.ps1
# Why: on this PC VirtualBox runs in Hyper-V mode; with under ~3 GB free RAM the VMs
# get paused by Windows, their clocks jump, boots hang and logins reset.

$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$order = "lab-router", "lab-web", "lab-db", "kali-linux-2026.2-virtualbox-amd64"

function FreeGB { [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1) }

# 1. Memory check
$heavy = Get-Process chrome, msedge, brave -ErrorAction SilentlyContinue | Group-Object ProcessName
if ($heavy) {
    Write-Host "Still running (even if windows are closed): $($heavy.Name -join ', ')" -ForegroundColor Yellow
    Write-Host "Close them fully (including background) before the demo." -ForegroundColor Yellow
}
$free = FreeGB
Write-Host "Free RAM before start: $free GB (lab needs about 4.5 GB; keep 3 GB spare)"
if ($free -lt 6.5) {
    Write-Host "WARNING: under 6.5 GB free - VMs may freeze. Close more apps, then rerun." -ForegroundColor Red
    $answer = Read-Host "Start anyway? (y/n)"
    if ($answer -ne "y") { exit 1 }
}

# 2. Start one at a time
foreach ($vm in $order) {
    $state = (& $vb showvminfo $vm --machinereadable | Select-String '^VMState=') -replace 'VMState=|"', ''
    if ($state -eq "running") {
        Write-Host "$vm already running"
        continue
    }
    Write-Host "Starting $vm ..." -ForegroundColor Cyan
    & $vb startvm $vm --type gui | Out-Null
    Start-Sleep 75
    Write-Host ("  free RAM now: {0} GB" -f (FreeGB))
}

Write-Host ""
Write-Host "All VMs started. Free RAM: $(FreeGB) GB" -ForegroundColor Green
Write-Host "Next: log in to router (adithya), web (labdb), kali (kali). lab-db needs no login."
Write-Host "Then on lab-router:  sudo firewall-baseline.sh"
