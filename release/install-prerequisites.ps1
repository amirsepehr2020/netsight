$ErrorActionPreference = 'Stop'

function Test-WebView2 {
  $paths = @(
    "$env:ProgramFiles (x86)\Microsoft\EdgeWebView\Application",
    "$env:ProgramFiles\Microsoft\EdgeWebView\Application"
  )
  return ($paths | Where-Object { Test-Path $_ }).Count -gt 0
}

function Test-Npcap {
  $service = Get-Service -Name npcap -ErrorAction SilentlyContinue
  return $null -ne $service
}

if (-not (Test-WebView2)) {
  Write-Warning 'Microsoft Edge WebView2 Runtime is not detected.'
  Write-Host 'Install the Evergreen WebView2 Runtime from Microsoft before launching NetSight.'
}

if (-not (Test-Npcap)) {
  Write-Warning 'Npcap is not detected.'
  Write-Host 'Install Npcap in WinPcap-compatible mode before starting packet capture.'
}

if ((Test-WebView2) -and (Test-Npcap)) {
  Write-Host 'NetSight prerequisites are ready.'
}
