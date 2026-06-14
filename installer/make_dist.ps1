# Baut ein sauberes dist/-Verzeichnis mit NUR den Laufzeitdateien der GUI.
# (Keine Build-Reste wie CMakeFiles/*_autogen.) Vorbereitung fürs Inno-Setup.
$ErrorActionPreference = "Stop"
$root  = Split-Path -Parent $PSScriptRoot          # ...\V7
$build = Join-Path $root "build-rel"
$dist  = Join-Path $root "dist"

if (-not (Test-Path "$build\dgkn_gui.exe")) { throw "dgkn_gui.exe fehlt - erst bauen." }

# dist neu aufsetzen.
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Force $dist | Out-Null

# 1) Haupt-exe.
Copy-Item "$build\dgkn_gui.exe" $dist -Force

# 2) Alle Laufzeit-DLLs (Qt, sodium, argon2, qrencode, winfsp, d3d, opengl ...).
Get-ChildItem "$build\*.dll" | Copy-Item -Destination $dist -Force

# 3) Qt-Plugin-Ordner (nur die echten Runtime-Plugins, keine Build-Ordner).
$pluginDirs = @("platforms","styles","imageformats","iconengines","tls",
                "networkinformation","generic")
foreach ($d in $pluginDirs) {
    if (Test-Path "$build\$d") { Copy-Item "$build\$d" $dist -Recurse -Force }
}

# 4) VC++-Runtime-Installer (optional, falls von windeployqt mitgeliefert).
if (Test-Path "$build\vc_redist.x64.exe") { Copy-Item "$build\vc_redist.x64.exe" $dist -Force }

# 5) Lizenz + Drittanbieter-Lizenztexte (Pflicht: Open-Source-Notices müssen mit
#    ausgeliefert werden — gilt auch fürs portable/SFX-Paket, das aus dist/ gebaut wird).
Copy-Item "$root\LICENSE" (Join-Path $dist "LICENSE.txt") -Force
foreach ($lic in @("THIRD-PARTY-NOTICES.txt","LGPL-3.0.txt","GPL-3.0.txt","LGPL-2.1.txt")) {
    if (Test-Path "$root\$lic") { Copy-Item "$root\$lic" $dist -Force }
    else { Write-Warning "Lizenzdatei fehlt: $lic (sollte im Repo-Root liegen)" }
}

# Ergebnis melden.
$count = (Get-ChildItem $dist -Recurse -File | Measure-Object).Count
$size  = [math]::Round((Get-ChildItem $dist -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "dist/ erstellt: $count Dateien, $size MB"
Write-Host "Pfad: $dist"

