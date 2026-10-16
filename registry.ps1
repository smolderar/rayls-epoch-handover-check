$Host.UI.RawUI.WindowTitle = "Registry check"
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
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmm")
.\epochcheck.exe -registry -out data-registry -report "registry-$stamp-UTC.txt"
Write-Host ""
Write-Host "Finished. Saved as registry-$stamp-UTC.txt"
