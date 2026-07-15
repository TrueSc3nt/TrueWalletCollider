param(
  [Parameter(Mandatory=$true)][string]$Url,
  [Parameter(Mandatory=$true)][string]$OutFile
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "[*] GET $Url"
Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
if (-not (Test-Path -LiteralPath $OutFile) -or ((Get-Item -LiteralPath $OutFile).Length -lt 1000)) {
  throw "download too small or missing: $OutFile"
}
Write-Host ("[+] saved {0} ({1} bytes)" -f $OutFile, (Get-Item -LiteralPath $OutFile).Length)
