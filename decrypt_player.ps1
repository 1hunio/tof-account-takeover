param([Parameter(Mandatory, Position=0)][string]$GamePath)

Add-Type -AssemblyName System.Security
$entropy = [System.Text.Encoding]::ASCII.GetBytes("gfsa97538uoxdrwp`0")
$path = Join-Path $GamePath "HottaLaunch\UserData\cache\player_v3_0"

foreach ($hex in ([System.IO.File]::ReadAllText($path) -split "\r?\n" | Where-Object { $_.Trim() })) {
    $raw = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $raw.Length; $i++) { $raw[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16) }
    $deobf = [byte[]]::new($raw.Length)
    for ($i = 0; $i -lt $raw.Length; $i++) { $deobf[$i] = (($raw[$i] -bxor 0xAB) - 1) -band 0xFF }
    $pt = [System.Security.Cryptography.ProtectedData]::Unprotect($deobf, $entropy, "CurrentUser")
    $ptHex = [System.Text.Encoding]::ASCII.GetString($pt)
    $dec = [byte[]]::new($ptHex.Length / 2)
    for ($i = 0; $i -lt $dec.Length; $i++) { $dec[$i] = [Convert]::ToByte($ptHex.Substring($i*2, 2), 16) }
    $a = [System.Text.Encoding]::ASCII.GetString($dec)
    $o = 0
    $secret = $a.Substring($o, 260).TrimEnd([char]0); $o += 260
    $uid    = $a.Substring($o, 260).TrimEnd([char]0); $o += 520
    $o += 64 + 4
    $ts     = $a.Substring($o, 260).TrimEnd([char]0)
    Write-Host "$secret $uid $ts"
}
