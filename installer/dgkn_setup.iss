; ============================================================================
;  DGKN@Labs Crypto Suite — Inno Setup Script
;  Erzeugt eine einzelne DGKN-Setup.exe auf dem Desktop.
;  Bündelt dgkn_gui.exe + alle Laufzeit-DLLs + Qt-Plugins, legt Startmenü-/
;  Desktop-Verknüpfung an, bietet (falls vorhanden) die VC++-Runtime-Installation,
;  und weist auf den optionalen WinFsp-Treiber hin.
; ============================================================================

#define AppName        "DGKN@Labs Crypto Suite"
#define AppVersion     "7.0.0"
#define AppPublisher   "DGKN@Labs"
#define AppExe         "dgkn_gui.exe"
; Quelle = das aufbereitete dist-Verzeichnis (nur Laufzeitdateien, keine Build-Reste).
#define DistDir        "..\dist"

[Setup]
AppId={{8F3D2A10-DGKN-4C7E-9B21-CRYPTOSUITE7}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\DGKN@Labs\Crypto Suite
DefaultGroupName=DGKN@Labs Crypto Suite
UninstallDisplayIcon={app}\{#AppExe}
; Wo die fertige Setup.exe landet + wie sie heißt. Der Desktop-Pfad wird beim
; Kompilieren per /O-Schalter überschrieben (siehe build_installer.ps1), daher hier
; nur ein Default.
OutputDir=.
OutputBaseFilename=DGKN-Setup
SetupIconFile={#SourcePath}\..\gui\icon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Lizenz + Drittanbieter-Notices im Setup-Assistenten anzeigen (LGPL/MIT/ISC-Pflicht:
; die Lizenztexte müssen den Nutzer erreichen). LicenseFile zeigt die DGKN-Lizenz;
; die Drittanbieter-Notices werden zusätzlich mitinstalliert (siehe [Files]).
LicenseFile={#SourcePath}\..\LICENSE
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Setup darf ohne Adminrechte pro-User installieren; mit Adminrechten für alle.
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Komplettes dist-Verzeichnis rekursiv (exe, DLLs, Qt-Plugin-Unterordner).
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; Lizenz + Drittanbieter-Lizenzhinweise neben die App legen (rechtliche Pflicht:
; die Texte der Open-Source-Komponenten müssen beim Endnutzer ankommen).
Source: "{#SourcePath}\..\LICENSE";                  DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#SourcePath}\..\THIRD-PARTY-NOTICES.txt";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\LGPL-3.0.txt";              DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourcePath}\..\GPL-3.0.txt";               DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourcePath}\..\LGPL-2.1.txt";              DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; VC++-Runtime mitliefern (wird in [Run] bei Bedarf still ausgeführt).
Source: "{#DistDir}\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: VcRedistPresent

[Icons]
Name: "{group}\DGKN@Labs Crypto Suite"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,DGKN@Labs Crypto Suite}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\DGKN@Labs Crypto Suite"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; VC++-Runtime still installieren (falls mitgeliefert).
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; \
  StatusMsg: "Installiere Visual C++ Runtime..."; Flags: waituntilterminated skipifdoesntexist; Check: VcRedistPresent
; App nach Abschluss optional starten.
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,DGKN@Labs Crypto Suite}"; \
  Flags: nowait postinstall skipifsilent

[Code]
function VcRedistPresent: Boolean;
begin
  Result := FileExists(ExpandConstant('{#DistDir}\vc_redist.x64.exe'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Hinweis auf WinFsp (Kernel-Treiber für das virtuelle Laufwerk).
    MsgBox('Hinweis: Für das virtuelle Laufwerk (Mount als echtes Laufwerk) wird der'
      + #13#10 + 'WinFsp-Treiber benötigt. Datei-Ver-/Entschlüsselung funktioniert auch ohne.'
      + #13#10#13#10 + 'WinFsp: https://winfsp.dev', mbInformation, MB_OK);
  end;
end;
