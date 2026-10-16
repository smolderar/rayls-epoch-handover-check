$Host.UI.RawUI.WindowTitle = "Epoch handover check"
Set-Location $PSScriptRoot
Write-Host "Preparing, please wait..."
Remove-Item .\epochcheck.exe -ErrorAction SilentlyContinue
go mod tidy *> build-log.txt
go build -o epochcheck.exe . *>> build-log.txt
if (-not (Test-Path .\epochcheck.exe)) {
  Write-Host "Build failed. Close this window and tell me."
  exit
}
Clear-Host
Write-Host "Ready. Start the screen recording, then press Enter."
[void](Read-Host)
Clear-Host
.\epochcheck.exe -out data-live -report report.txt -show 167 -split 134
Write-Host ""
Write-Host "Finished. You can stop the recording now."
