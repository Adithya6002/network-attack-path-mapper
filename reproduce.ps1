# Re-runs every check and regenerates every number in PROJECT.md (about 5 minutes).
# Usage (PowerShell, from the project folder):  .\reproduce.ps1
# Needs no network and no VMs: the lab measurements are read from evidence\measurements.csv.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    py -m venv .venv
    & $py -m pip install -q -r requirements.txt
}

Write-Host "`n[1/5] Automated tests" -ForegroundColor Cyan
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "`n[2/5] Sample network: before/after segmentation (section 6)" -ForegroundColor Cyan
& $py main.py compare --start 10.10.10.5 --after data/firewall_segmented.json --html-dir output

Write-Host "`n[3/5] Lab validation: model vs. 72 measured connections (section 8)" -ForegroundColor Cyan
& $py lab\compare_results.py data\lab.json evidence\measurements.csv

Write-Host "`n[4/5] Real lab network: before/after segmentation (section 8.2)" -ForegroundColor Cyan
& $py main.py compare --data data/lab.json --start 10.10.10.5 --after data/firewall_segmented.json --html-dir evidence

Write-Host "`n[5/5] Large-network experiments and figures (section 8A)" -ForegroundColor Cyan
& $py -m experiments.run_experiments | Select-Object -First 3
& $py -m experiments.plot_results

Write-Host "`nDone. Results: output\, evidence\, experiments\results\" -ForegroundColor Green
