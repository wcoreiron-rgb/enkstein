#ifndef Version
  #define Version "0.8.2"
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
AppPublisherURL=https://github.com/wcoreiron-rgb/enkstein
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
Source: "{#StageDir}\Enkstein.ico"; DestDir: "{app}"; Flags: ignoreversion
; WebView2 SDK assemblies and native loader. The host embeds WebView2, so it
; cannot start without these beside the executable.
Source: "{#StageDir}\Microsoft.Web.WebView2.Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\Microsoft.Web.WebView2.WinForms.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\WebView2Loader.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; AppUserModelID must match AppIdentity.AppUserModelId in the launcher, otherwise
; a pinned shortcut and the running window are treated as two different apps and
; the taskbar shows a duplicate button.
Name: "{autoprograms}\Enkstein"; Filename: "{app}\Enkstein.exe"; IconFilename: "{app}\Enkstein.ico"; AppUserModelID: "Enkstein.Desktop"
Name: "{autodesktop}\Enkstein"; Filename: "{app}\Enkstein.exe"; IconFilename: "{app}\Enkstein.ico"; AppUserModelID: "Enkstein.Desktop"; Tasks: desktopicon

[InstallDelete]
; Remove shortcuts from the pre-rename builds. Without this an upgrade leaves a
; dead legacy tile beside the new "Enkstein" one, which is the duplicate
; shortcut the acceptance criteria call out.
Type: files; Name: "{autoprograms}\Marcellus.lnk"
Type: files; Name: "{autodesktop}\Marcellus.lnk"
Type: filesandordirs; Name: "{autoprograms}\Marcellus"
Type: files; Name: "{autoprograms}\RegentClaw.lnk"
Type: files; Name: "{autodesktop}\RegentClaw.lnk"
Type: filesandordirs; Name: "{autoprograms}\RegentClaw"

[UninstallDelete]
; The WebView2 user-data folder is created at runtime, so the uninstaller does
; not know about it and would otherwise leave it behind.
Type: filesandordirs; Name: "{localappdata}\Enkstein\WebView2"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Enkstein.exe"; Description: "Start Enkstein"; Flags: nowait postinstall skipifsilent
