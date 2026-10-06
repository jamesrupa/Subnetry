; Inno Setup script for the Subnetry Windows installer.
;   iscc /DAppVersion=1.2.3 packaging\windows\subnetry.iss
; Expects the PyInstaller output in dist\Subnetry (see build.ps1). Produces dist\Subnetry-Setup-windows-x64.exe

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8C1B6E2A-5F3D-4C7B-9A1E-2D4F6B8C0A13}
AppName=Subnetry
AppVersion={#AppVersion}
AppVerName=Subnetry {#AppVersion}
AppPublisher=Subnetry
AppPublisherURL=https://github.com/jamesrupa/subnetry
AppSupportURL=https://github.com/jamesrupa/subnetry/issues
; Per-user install: no administrator prompt for Subnetry itself.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\Subnetry
DefaultGroupName=Subnetry
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=Subnetry-Setup-windows-x64
SetupIconFile=..\..\subnetry\desktop\Subnetry.ico
UninstallDisplayIcon={app}\Subnetry.exe
UninstallDisplayName=Subnetry
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
MinVersion=10.0

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"
Name: "speedtest"; Description: "Speedtest.net CLI: official Speedtest.net results in Speed Test (small download)"; GroupDescription: "Optional tools (free):"; Check: not HasSpeedtest
Name: "nmap"; Description: "Nmap: needed for the Port Scanner (opens the Nmap installer; keep Npcap ticked)"; GroupDescription: "Optional tools (free):"; Check: not HasNmap
Name: "wireshark"; Description: "Wireshark: needed for the Traffic Analyzer (opens the Wireshark installer; keep Npcap and TShark ticked)"; GroupDescription: "Optional tools (free):"; Check: not HasWireshark

[Files]
Source: "..\..\dist\Subnetry\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Files from a previous version that might not be overwritten.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\Subnetry"; Filename: "{app}\Subnetry.exe"; Comment: "Network analysis and diagnostics"
Name: "{autodesktop}\Subnetry"; Filename: "{app}\Subnetry.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Subnetry.exe"; Parameters: "--install-tool speedtest"; StatusMsg: "Installing the Speedtest.net CLI..."; Tasks: speedtest; Flags: runhidden waituntilterminated
; winget opens each tool's official installer (Windows asks for permission). Without winget, the download page opens.
Filename: "{cmd}"; Parameters: "/c winget install -e --id Insecure.Nmap --interactive --accept-package-agreements --accept-source-agreements || start """" https://nmap.org/download.html#windows"; StatusMsg: "Opening the Nmap installer..."; Tasks: nmap; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/c winget install -e --id WiresharkFoundation.Wireshark --interactive --accept-package-agreements --accept-source-agreements || start """" https://www.wireshark.org/download.html"; StatusMsg: "Opening the Wireshark installer..."; Tasks: wireshark; Flags: runhidden waituntilterminated
Filename: "{app}\Subnetry.exe"; Description: "Open Subnetry now"; Flags: nowait postinstall skipifsilent

[Code]
function HasNmap: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf32}\Nmap\nmap.exe')) or FileExists(ExpandConstant('{commonpf64}\Nmap\nmap.exe'));
end;

function HasWireshark: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\Wireshark\tshark.exe')) or FileExists(ExpandConstant('{commonpf32}\Wireshark\tshark.exe'));
end;

function HasSpeedtest: Boolean;
begin
  Result := FileExists(ExpandConstant('{localappdata}\Subnetry\bin\speedtest.exe')) or
            FileExists(ExpandConstant('{commonpf64}\Ookla\Speedtest CLI\speedtest.exe'));
end;
