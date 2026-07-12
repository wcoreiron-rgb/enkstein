#ifndef Version
  #define Version "0.7.0"
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif

[Setup]
AppId={{A447FC72-3E47-42EF-B68F-E108CFC1258A}
AppName=RegentClaw
AppVersion={#Version}
AppPublisher=RegentClaw
AppPublisherURL=https://github.com/wcoreiron-rgb/regentclaw
DefaultDirName={localappdata}\Programs\RegentClaw
DefaultGroupName=RegentClaw
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=RegentClaw-{#Version}-windows-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#StageDir}\RegentClaw.ico
UninstallDisplayIcon={app}\RegentClaw.exe
LicenseFile={#StageDir}\runtime\LICENSE

[Files]
Source: "{#StageDir}\RegentClaw.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\RegentClaw"; Filename: "{app}\RegentClaw.exe"
Name: "{autodesktop}\RegentClaw"; Filename: "{app}\RegentClaw.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\RegentClaw.exe"; Description: "Start RegentClaw"; Flags: nowait postinstall skipifsilent
