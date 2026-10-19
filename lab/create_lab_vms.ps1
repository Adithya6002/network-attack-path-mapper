# Creates the empty lab VMs and wires them to isolated VirtualBox internal networks.
# Run from the project folder in PowerShell:  .\lab\create_lab_vms.ps1
# Existing VMs with the same names are skipped, never overwritten.

$ErrorActionPreference = "Stop"
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$vmRoot = Join-Path $env:USERPROFILE "VirtualBox VMs"

# name, ostype, RAM MB, CPUs, disk GB, NICs (internal network names; "nat" = temporary internet)
$vms = @(
    @{ Name = "lab-router"; Os = "Ubuntu_64"; Ram = 1024; Cpu = 1; Disk = 10; Nics = @("lab-user-lan", "lab-dmz", "lab-internal", "nat") },
    @{ Name = "lab-web";    Os = "Ubuntu_64"; Ram = 1024; Cpu = 1; Disk = 10; Nics = @("lab-dmz", "nat") },
    @{ Name = "lab-db";     Os = "Ubuntu_64"; Ram = 1024; Cpu = 1; Disk = 10; Nics = @("lab-internal", "nat") }
)

$existing = & $vbox list vms

foreach ($vm in $vms) {
    if ($existing -match "`"$($vm.Name)`"") {
        Write-Host "Skipping $($vm.Name): already exists"
        continue
    }
    Write-Host "Creating $($vm.Name)"
    & $vbox createvm --name $vm.Name --ostype $vm.Os --register --groups "/cn-lab" | Out-Null
    & $vbox modifyvm $vm.Name --memory $vm.Ram --cpus $vm.Cpu --audio-enabled off --usb off --clipboard-mode disabled --drag-and-drop disabled

    for ($i = 0; $i -lt $vm.Nics.Count; $i++) {
        $n = $i + 1
        if ($vm.Nics[$i] -eq "nat") {
            & $vbox modifyvm $vm.Name "--nic$n" nat
        } else {
            & $vbox modifyvm $vm.Name "--nic$n" intnet "--intnet$n" $vm.Nics[$i]
        }
    }

    $disk = Join-Path $vmRoot "cn-lab\$($vm.Name)\$($vm.Name).vdi"
    & $vbox createmedium disk --filename $disk --size ($vm.Disk * 1024) | Out-Null
    & $vbox storagectl $vm.Name --name SATA --add sata --controller IntelAhci
    & $vbox storageattach $vm.Name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
    & $vbox storageattach $vm.Name --storagectl SATA --port 1 --device 0 --type dvddrive --medium emptydrive
}

Write-Host ""
Write-Host "Done. Next: attach the Ubuntu Server ISO to each VM's DVD drive and install (see lab/LAB_SETUP.md, step 3)."
Write-Host "Kali and Metasploitable are imported from their prebuilt images (steps 5 and 6)."
