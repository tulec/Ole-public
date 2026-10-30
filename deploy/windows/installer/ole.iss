#ifndef OLEVersion
  #define OLEVersion "0.1.0"
#endif

#ifndef OLESourceDir
  #define OLESourceDir "..\..\..\dist\windows-installer\stage"
#endif

#ifndef OLEOutputDir
  #define OLEOutputDir "..\..\..\dist\windows-installer\out"
#endif

#define MyAppName "Ole"
#define MyAppPublisher "Ole"
#define MyAppURL "https://github.com/openai/unknown"
#define MyAppExeName "ole-client.exe"
#define MyAgentExeName "ole-agent.exe"

[Setup]
AppId={{74BB2CAF-0F7B-45C3-A27F-D4D4C3C4E5B2}
AppName={#MyAppName}
AppVersion={#OLEVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Ole
DefaultGroupName=Ole
OutputDir={#OLEOutputDir}
OutputBaseFilename=Ole-Setup-{#OLEVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
ChangesAssociations=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "{#OLESourceDir}\ole-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OLESourceDir}\ole-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OLESourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\Ole"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Ole"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAgentExeName}"; Parameters: "install"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAgentExeName}"; Parameters: "start"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Ole"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#MyAgentExeName}"; Parameters: "stop"; Flags: runhidden waituntilterminated skipifdoesntexist
Filename: "{app}\{#MyAgentExeName}"; Parameters: "uninstall"; Flags: runhidden waituntilterminated skipifdoesntexist

[Code]
function TryExecAgent(Command: String): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not FileExists(ExpandConstant('{app}\{#MyAgentExeName}')) then
    exit;
  if Exec(ExpandConstant('{app}\{#MyAgentExeName}'), Command, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  TryExecAgent('stop');
  TryExecAgent('uninstall');
  Result := '';
end;
