; SocketForge installer (Inno Setup 6). Installs for the current user; no administrator rights needed.

#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
; Where cargo put the build (scripts\package.ps1 passes CARGO_TARGET_DIR when it is set).
#ifndef TargetDir
  #define TargetDir "..\target"
#endif

[Setup]
AppId={{4D9E7A15-63C2-4B8F-9E0A-7C1F5D2B8A36}
AppName=SocketForge
AppVersion={#AppVersion}
AppVerName=SocketForge {#AppVersion}
AppPublisher=Zheer Khalid
AppPublisherURL=https://zheer.dev
AppSupportURL=https://github.com/zheerkhalid/socketforge
AppUpdatesURL=https://github.com/zheerkhalid/socketforge/releases
DefaultDirName={autopf}\SocketForge
DefaultGroupName=SocketForge
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=SocketForge-Setup
SetupIconFile={#TargetDir}\socketforge.ico
UninstallDisplayIcon={app}\SocketForge.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Zheer Khalid (zheer.dev)
VersionInfoDescription=SocketForge Setup

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#TargetDir}\release\SocketForge.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\SocketForge"; Filename: "{app}\SocketForge.exe"
Name: "{group}\Uninstall SocketForge"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SocketForge"; Filename: "{app}\SocketForge.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SocketForge.exe"; Description: "{cm:LaunchProgram,SocketForge}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM SocketForge.exe /F"; Flags: runhidden; RunOnceId: "KillSocketForge"

[UninstallDelete]
; Settings, history, hosts profiles and hosts backups live in %LOCALAPPDATA%\SocketForge and
; are deliberately left in place: the backups may be the only copy of an older hosts file.
