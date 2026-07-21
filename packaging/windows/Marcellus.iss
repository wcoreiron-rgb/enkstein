#ifndef Version
  #define Version "0.3.11"
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif

[Setup]
AppId={{DDA57C8B-77E6-4A52-B56D-5CA5EAFE8C19}
AppName=Enkstein
AppVersion={#Version}
AppPublisher=Enkstein
AppPublisherURL=https://github.com/wcoreiron-rgb/marcellus
DefaultDirName={localappdata}\Programs\Enkstein
DefaultGroupName=Enkstein
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=Enkstein-{#Version}-windows-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#StageDir}\Enkstein.ico
UninstallDisplayIcon={app}\Enkstein.exe
LicenseFile={#StageDir}\runtime\LICENSE

[Files]
Source: "{#StageDir}\Enkstein.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Enkstein"; Filename: "{app}\Enkstein.exe"
Name: "{autodesktop}\Enkstein"; Filename: "{app}\Enkstein.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Enkstein.exe"; Description: "Start Enkstein"; Flags: nowait postinstall skipifsilent
