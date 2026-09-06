$ErrorActionPreference = "Continue"
$root = "F:\Projects\WebTransport"

Get-Process bun -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item "$root\server-out.log", "$root\server-err.log", "$root\client-*.log" -Force -ErrorAction SilentlyContinue

$procs = [int]$args[0]   # client processes
$clients = $args[1]      # clients per process
$rate = $args[2]         # sends per client per second
$dur = $args[3]          # seconds
$payload = $args[4]      # payload bytes (optional)
$mode = $args[5]         # "echo" (default) or "relay" (optional)
$burst = $args[6]        # back-to-back sends per tick (optional)
$serverWorkUs = $args[7] # per-datagram CPU burn on the server (optional)
$clientWorkUs = $args[8] # per-datagram CPU burn on the client (optional)

$serverArgs = "bench/stress-server.ts 90"
if ($mode -eq "relay") { $serverArgs = "bench/stress-server.ts 90 --relay 4" }
if ($serverWorkUs) { $serverArgs = "$serverArgs --work-us $serverWorkUs" }

$cmd = 'cmd /c "cd /d F:\Projects\WebTransport && C:\Users\Lillious\.bun\bin\bun.exe ' + $serverArgs + ' > server-out.log 2> server-err.log"'
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"server pid=$($created.ProcessId)"

$m = $null
for ($i = 0; $i -lt 30; $i++) {
  $m = Get-Content "$root\server-out.log" -ErrorAction SilentlyContinue | Select-String "PORT (\d+) HASH ([0-9a-f]+)" | Select-Object -First 1
  if ($m) { break }
  Start-Sleep -Milliseconds 500
}
if (-not $m) { "SERVER FAILED TO START"; Get-Content "$root\server-err.log" -ErrorAction SilentlyContinue; exit 1 }
$port = $m.Matches[0].Groups[1].Value
$hash = $m.Matches[0].Groups[2].Value
"server ready: port=$port  launching $procs client processes x $clients clients"

$pids = @()
for ($k = 0; $k -lt $procs; $k++) {
  $clientArgs = @("bench/stress-clients.ts", $port, $hash, $clients, $rate, $dur)
  $clientArgs += $(if ($payload) { $payload } else { 24 })
  $clientArgs += $(if ($mode -eq "relay") { "relay" } else { "echo" })
  $clientArgs += $(if ($burst) { $burst } else { 1 })
  $clientArgs += $(if ($clientWorkUs) { $clientWorkUs } else { 0 })
  $p = Start-Process -FilePath "C:\Users\Lillious\.bun\bin\bun.exe" -ArgumentList $clientArgs -WorkingDirectory $root -PassThru -NoNewWindow -RedirectStandardOutput "$root\client-$k.log" -RedirectStandardError "$root\client-err-$k.log"
  $pids += $p.Id
}
"client pids: $($pids -join ' ')"
Wait-Process -Id $pids -Timeout 240 -ErrorAction SilentlyContinue

Get-Process bun -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
for ($k = 0; $k -lt $procs; $k++) {
  "=== CLIENT $k ==="
  Get-Content "$root\client-$k.log" -Raw -ErrorAction SilentlyContinue
}
"=== SERVER ==="
Get-Content "$root\server-out.log" -Raw -ErrorAction SilentlyContinue
"=== SERVER ERR ==="
Get-Content "$root\server-err.log" -Raw -ErrorAction SilentlyContinue
