# Baut eine selbstentpackende DGKN-Setup.exe aus dem dist/-Verzeichnis (7-Zip SFX).
# Beim Doppelklick: entpackt nach %LOCALAPPDATA%\DGKN@Labs\Crypto Suite und startet die App.
# Kein Inno Setup, kein Adminrecht noetig. Aendert nichts am Projekt.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot          # ...\V7
$dist = Join-Path $root "dist"
$desktop = [Environment]::GetFolderPath("Desktop")
$out  = Join-Path $desktop "DGKN-Setup.exe"

$sevenZip = "C:\Program Files\7-Zip\7z.exe"
$sfxModule = "C:\Program Files\7-Zip\7z.sfx"      # GUI-SFX-Modul
if (-not (Test-Path $sevenZip)) { throw "7-Zip nicht gefunden." }
if (-not (Test-Path $dist))     { throw "dist/ fehlt - erst installer\make_dist.ps1 laufen lassen." }

$tmp = Join-Path $env:TEMP "dgkn_sfx"
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
New-Item -ItemType Directory -Force $tmp | Out-Null

# 1) dist als 7z-Archiv packen.
$archive = Join-Path $tmp "payload.7z"
& $sevenZip a -t7z -mx=7 "$archive" "$dist\*" | Out-Null
if (-not (Test-Path $archive)) { throw "7z-Archiv konnte nicht erstellt werden." }

# 2) SFX-Konfiguration: Zielordner + Auto-Start der GUI nach dem Entpacken.
$config = Join-Path $tmp "config.txt"
@"
;!@Install@!UTF-8!
Title="DGKN@Labs Crypto Suite v7"
BeginPrompt="DGKN@Labs Crypto Suite installieren und starten?"
ExtractTitle="Entpacke DGKN@Labs Crypto Suite..."
InstallPath="%LOCALAPPDATA%\\DGKN@Labs\\Crypto Suite"
RunProgram="dgkn_gui.exe"
GUIMode="1"
;!@InstallEnd@!
"@ | Set-Content -Path $config -Encoding UTF8

# 3) SFX-Modul + Config + Archiv zur finalen Setup.exe zusammenfuegen.
$fsModule  = [IO.File]::ReadAllBytes($sfxModule)
$fsConfig  = [IO.File]::ReadAllBytes($config)
$fsArchive = [IO.File]::ReadAllBytes($archive)
$fs = New-Object IO.FileStream($out, [IO.FileMode]::Create)
$fs.Write($fsModule, 0, $fsModule.Length)
$fs.Write($fsConfig, 0, $fsConfig.Length)
$fs.Write($fsArchive, 0, $fsArchive.Length)
$fs.Close()

Remove-Item $tmp -Recurse -Force
$mb = [math]::Round((Get-Item $out).Length / 1MB, 1)
Write-Host "DGKN-Setup.exe erstellt: $out ($mb MB)"

