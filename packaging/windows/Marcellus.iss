#ifndef Version
  #define Version "0.2.0"
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif

[Setup]
AppId={{DDA57C8B-77E6-4A52-B56D-5CA5EAFE8C19}
AppName=Marcellus
AppVersion={#Version}
AppPublisher=Marcellus
AppPublisherURL=https://github.com/wcoreiron-rgb/marcellus
DefaultDirName={localappdata}\Programs\Marcellus
DefaultGroupName=Marcellus
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=Marcellus-{#Version}-windows-x64-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile={#StageDir}\Marcellus.ico
UninstallDisplayIcon={app}\Marcellus.exe
LicenseFile={#StageDir}\runtime\LICENSE

[Files]
Source: "{#StageDir}\Marcellus.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Marcellus"; Filename: "{app}\Marcellus.exe"
Name: "{autodesktop}\Marcellus"; Filename: "{app}\Marcellus.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Marcellus.exe"; Description: "Start Marcellus"; Flags: nowait postinstall skipifsilent
