# Prepare the final-review demonstration from saved evidence; no live scanning.
# Run .\review_demo.ps1 from PowerShell. It does not recreate the Linux lab.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$projectPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $projectPython)) { throw "Create .venv and install requirements-lock.txt first." }

Write-Host "`n[1/5] Automated tests" -ForegroundColor Cyan
& $projectPython -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

Write-Host "`n[2/5] Sample: direct exposure becomes a web-server choke point" -ForegroundColor Cyan
& $projectPython main.py compare --start 10.10.10.5 --after data/firewall_segmented.json --html-dir output/final_review/sample --json output/final_review/sample.json
if ($LASTEXITCODE -ne 0) { throw "Sample comparison failed" }

Write-Host "`n[3/5] Expanded lab: compare saved real observations with model predictions" -ForegroundColor Cyan
& $projectPython lab/validate_namespace.py evidence/namespace_lab_2026-10-28
if ($LASTEXITCODE -ne 0) { throw "Expanded lab evidence did not validate" }

Write-Host "`n[4/5] Expanded lab: host firewalls reduce local-segment exposure" -ForegroundColor Cyan
& $projectPython main.py compare --data evidence/namespace_lab_2026-10-28/segmented.json --start 10.44.10.11 --after evidence/namespace_lab_2026-10-28/hardened.json --html-dir output/final_review/host_firewalls --json output/final_review/host_firewalls.json
if ($LASTEXITCODE -ne 0) { throw "Host-firewall comparison failed" }

Write-Host "`n[5/5] Advisory hardening, preserving declared application connections" -ForegroundColor Cyan
& $projectPython main.py recommend --start 10.10.10.5 --required data/required_connections.json --json output/final_review/recommendations.json
if ($LASTEXITCODE -ne 0) { throw "Recommendation simulation failed" }

Write-Host "`nOpen output/final_review/sample/comparison.html and output/final_review/host_firewalls/comparison.html." -ForegroundColor Green
Write-Host "Large-network timings and memory: experiments/results/large_2026-10-28/summary.md"
Write-Host "Explain that recommendations are independent simulations and namespaces share one Linux kernel."
