$ErrorActionPreference = "Continue"
$root = "F:\Projects\WebTransport"

# 1. Kill everything from previous runs.
Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Google*Chrome*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process bun -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID -and $_.Path -like "*.bun*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 2. Start the server fully detached via WMI (no handle inheritance, returns immediately).
Remove-Item "$root\server-out.log", "$root\server-err.log" -Force -ErrorAction SilentlyContinue
$cmd = 'cmd /c "cd /d F:\Projects\WebTransport && C:\Users\Lillious\.bun\bin\bun.exe examples/04-chrome-interop.ts > server-out.log 2> server-err.log"'
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"server launched, pid=$($created.ProcessId)"

# 3. Poll for the page listener (bounded).
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
  $tcp = netstat -ano -p tcp | Select-String ":8099\s.*LISTENING"
  if ($tcp) { $ready = $true; break }
  Start-Sleep -Seconds 1
}
if (-not $ready) { "SERVER NOT READY"; Get-Content "$root\server-err.log" -ErrorAction SilentlyContinue; exit 1 }
"SERVER READY"

# 4. Run Chrome (headed, fresh profile), poll the server log for the page's
#    report, then kill Chrome.
Remove-Item "$root\netlog.json" -Force -ErrorAction SilentlyContinue
Remove-Item "$root\.chrome-profile" -Recurse -Force -ErrorAction SilentlyContinue
$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$chromeArgs = @(
  "--user-data-dir=$root\.chrome-profile",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-component-update",
  "--log-net-log=$root\netlog.json",
  "http://127.0.0.1:8099/"
)
$proc = Start-Process -FilePath $chrome -ArgumentList $chromeArgs -PassThru
"chrome pid=$($proc.Id)"

$result = $null
for ($i = 0; $i -lt 45; $i++) {
  Start-Sleep -Seconds 1
  $lines = Get-Content "$root\server-out.log" -ErrorAction SilentlyContinue
  $hit = $lines | Where-Object { $_ -like "chrome:*" } | Select-Object -Last 1
  if ($hit) { $result = $hit; break }
}
"poll result: $result"
Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Google*Chrome*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 5. Dump everything.
"=== SERVER OUT ==="
Get-Content "$root\server-out.log" -Raw -ErrorAction SilentlyContinue
"=== SERVER ERR ==="
Get-Content "$root\server-err.log" -Raw -ErrorAction SilentlyContinue
"=== NETLOG present: $(Test-Path "$root\netlog.json") size $((Get-Item "$root\netlog.json" -ErrorAction SilentlyContinue).Length)"
