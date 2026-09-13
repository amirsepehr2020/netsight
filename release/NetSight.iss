#define MyAppName "NetSight"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "NetSight"
#define MyAppExeName "netsight-desktop.exe"

[Setup]
AppId={{7B4D4B1A-8D0D-4E2D-9E2B-7C2D5F7E5A10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion} RC1
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\NetSight
DefaultGroupName=NetSight
OutputDir=dist
OutputBaseFilename=NetSight-Setup-{#MyAppVersion}-rc.1
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\netsight-desktop.exe
SetupIconFile=dist\netsight.ico
WizardStyle=modern

[Files]
Source: "dist\netsight-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\netsight-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\netsight.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\ui\*"; DestDir: "{app}\ui"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetSight"; Filename: "{app}\netsight-desktop.exe"; IconFilename: "{app}\netsight.ico"
Name: "{commondesktop}\NetSight"; Filename: "{app}\netsight-desktop.exe"; IconFilename: "{app}\netsight.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-prerequisites.ps1"""; Flags: runhidden waituntilterminated skipifdoesntexist
Filename: "{app}\netsight-desktop.exe"; Description: "Launch NetSight"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\ui"
