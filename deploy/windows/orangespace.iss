; OrangeSpace Windows installer (Inno Setup 6.7). Built by scripts/build-release.ps1:
;   ISCC /DAppVersion=0.1.0 /DPayload=<staged folder> /DOutputDir=<folder> deploy\windows\orangespace.iss
; The staged folder holds OrangeSpace.exe, trust\ (Centre address and node
; pins of this deployment), system\ (root filesystem, desktop image,
; release.json) and licenses\.
;
; The installer is machine-wide: it checks the system, turns on WSL when it is
; missing (a restart may follow) and installs the files into an administrator-
; only folder. Each Windows user's distribution is created by OrangeSpace.exe
; on its first start (WSL distributions belong to one user) and upgraded in
; place, keeping that user's sandboxes, when a newer release is installed.

#ifndef AppVersion
  #error Pass /DAppVersion=x.y.z
#endif
#ifndef Payload
  #error Pass /DPayload=<staged folder>
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif

[Setup]
AppId={{6F1C9B2A-3D47-4E8B-9A15-2C7E0D4B8F31}
AppName=橙域 OrangeSpace
AppVersion={#AppVersion}
AppVerName=橙域 OrangeSpace {#AppVersion}
AppPublisher=OrangeSpace
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\OrangeSpace
; The trust files and the system image must stay administrator-only, which
; Program Files guarantees; no other folder is offered.
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 22H2 (19045) or later.
MinVersion=10.0.19045
AppMutex=OrangeSpace.Client,Global\OrangeSpace.Client
SetupMutex=OrangeSpace.Setup,Global\OrangeSpace.Setup
CloseApplications=no
WizardStyle=modern
SetupIconFile=..\..\apps\windows-client\src\orangespace.ico
UninstallDisplayIcon={app}\OrangeSpace.exe
UninstallDisplayName=橙域 OrangeSpace
OutputDir={#OutputDir}
OutputBaseFilename=OrangeSpace-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
LZMANumBlockThreads=4
DiskSpanning=no

[Tasks]
Name: "desktopicon"; Description: "在桌面创建快捷方式"; GroupDescription: "附加任务："

[InstallDelete]
; An upgrade replaces the system part and this deployment's trust files whole.
Type: filesandordirs; Name: "{app}\system"
Type: filesandordirs; Name: "{app}\trust"
Type: filesandordirs; Name: "{app}\licenses"

[Files]
Source: "{#Payload}\OrangeSpace.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Payload}\trust\*"; DestDir: "{app}\trust"; Flags: ignoreversion
Source: "{#Payload}\system\*"; DestDir: "{app}\system"; Flags: ignoreversion
Source: "{#Payload}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\橙域 OrangeSpace"; Filename: "{app}\OrangeSpace.exe"
Name: "{autodesktop}\橙域 OrangeSpace"; Filename: "{app}\OrangeSpace.exe"; Tasks: desktopicon

[Run]
; Administrators and SYSTEM own and may change the program folder; users may
; only read it. The client refuses trust files anyone else could change, and
; requires their folder and files to carry their own (non-inherited) ACL.
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /setowner *S-1-5-32-544 /T /C /Q"; Flags: runhidden waituntilterminated; StatusMsg: "正在设置文件权限……"
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /C /Q"; Flags: runhidden waituntilterminated; StatusMsg: "正在设置文件权限……"
Filename: "{sys}\icacls.exe"; Parameters: """{app}\*"" /reset /T /C /Q"; Flags: runhidden waituntilterminated; StatusMsg: "正在设置文件权限……"
Filename: "{sys}\icacls.exe"; Parameters: """{app}\trust"" /inheritance:d /T /C /Q"; Flags: runhidden waituntilterminated; StatusMsg: "正在设置文件权限……"
Filename: "{app}\OrangeSpace.exe"; Description: "启动橙域"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: not NeedRestart

[Messages]
SetupAppTitle=安装
SetupWindowTitle=安装 - %1
UninstallAppTitle=卸载
UninstallAppFullTitle=卸载 %1
ButtonBack=< 上一步(&B)
ButtonNext=下一步(&N) >
ButtonInstall=安装(&I)
ButtonOK=确定
ButtonCancel=取消
ButtonYes=是(&Y)
ButtonNo=否(&N)
ButtonFinish=完成(&F)
ButtonBrowse=浏览(&B)...
ButtonWizardBrowse=浏览(&R)...
ButtonNewFolder=新建文件夹(&M)
ExitSetupTitle=退出安装
ExitSetupMessage=安装尚未完成。现在退出，程序不会被安装。%n%n以后可以再次运行安装程序完成安装。%n%n要退出安装吗？
ConfirmTitle=确认
ErrorTitle=错误
SetupAlreadyRunning=安装程序已在运行。
WindowsVersionNotSupported=此程序不支持这台电脑上的 Windows 版本。
WinVersionTooLowError=%1 需要 %2 %3 或更高版本。
AdminPrivilegesRequired=安装此程序需要以管理员身份登录。
SetupAppRunningError=安装程序检测到 %1 正在运行。%n%n请先关闭它，然后点“确定”继续，或点“取消”退出。
UninstallAppRunningError=卸载程序检测到 %1 正在运行。%n%n请先关闭它，然后点“确定”继续，或点“取消”退出。
WelcomeLabel1=欢迎安装 [name]
WelcomeLabel2=将在这台电脑上安装 [name/ver]。%n%n每个沙盒是一个独立的 Linux 桌面，运行在 Windows 自带的 WSL 中，全部网络流量只经它绑定的节点出网。%n%n建议先关闭其他程序。
WizardReady=准备安装
ReadyLabel1=安装程序已准备好在这台电脑上安装 [name]。
ReadyLabel2a=点“安装”开始，或点“上一步”查看、修改设置。
ReadyLabel2b=点“安装”开始。
ReadyMemoDir=安装位置：
ReadyMemoTasks=附加任务：
WizardSelectTasks=选择附加任务
SelectTasksDesc=要执行哪些附加任务？
SelectTasksLabel2=选择安装 [name] 时要执行的附加任务，然后点“下一步”。
WizardPreparing=正在准备安装
PreparingDesc=安装程序正在准备在这台电脑上安装 [name]。
PrepareToInstallNeedsRestart=需要先重新启动电脑。重启后请再次运行安装程序完成安装 [name]。%n%n要现在重新启动吗？
WizardInstalling=正在安装
InstallingLabel=正在安装 [name]，请稍候。
FinishedHeadingLabel=[name] 安装完成
FinishedLabelNoIcons=[name] 已安装。
FinishedLabel=[name] 已安装，可以从开始菜单打开。
FinishedRestartLabel=要完成 [name] 的安装（启用 WSL），需要重新启动电脑。要现在重新启动吗？
FinishedRestartMessage=要完成 [name] 的安装（启用 WSL），需要重新启动电脑。%n%n要现在重新启动吗？
YesRadio=现在重新启动(&Y)
NoRadio=稍后自己重新启动(&N)
ClickFinish=点“完成”退出安装。
StatusClosingApplications=正在关闭程序……
StatusCreateDirs=正在创建文件夹……
StatusExtractFiles=正在复制文件……
StatusCreateIcons=正在创建快捷方式……
StatusCreateRegistryEntries=正在写入注册表……
StatusRegisterFiles=正在注册文件……
StatusSavingUninstall=正在保存卸载信息……
StatusRunProgram=正在完成安装……
StatusRollback=正在撤销已做的更改……
StatusUninstalling=正在卸载 %1……
StatusRestartingApplications=正在重新启动程序……
ConfirmUninstall=要卸载 %1 吗？
OnlyAdminCanUninstall=卸载此程序需要管理员权限。
UninstallStatusLabel=正在从这台电脑卸载 %1，请稍候。
WizardUninstalling=卸载状态
UninstalledAll=%1 已从这台电脑卸载。
UninstalledMost=%1 已卸载。%n%n有些内容没有删除，可以手动删除。
UninstalledAndNeedsRestart=要完成 %1 的卸载，需要重新启动电脑。%n%n要现在重新启动吗？
ErrorFunctionFailedNoCode=%1 失败
ErrorFunctionFailed=%1 失败，代码 %2
ErrorFunctionFailedWithMessage=%1 失败，代码 %2。%n%3
ErrorExecutingProgram=无法运行：%n%1
DiskSpaceGBLabel=至少需要 [gb] GB 可用磁盘空间。
DiskSpaceMBLabel=至少需要 [mb] MB 可用磁盘空间。

[Code]
var
  RestartNeeded: Boolean;

// Hardware virtualization: a hypervisor already runs (WSL or Hyper-V on), or
// the firmware has it on. WMI failing is not taken as "absent".
function VirtualizationAvailable(): Boolean;
var
  Locator, Service, Items, Item: Variant;
  I: Integer;
begin
  Result := True;
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('.', 'root\CIMV2');
    Items := Service.ExecQuery('SELECT HypervisorPresent FROM Win32_ComputerSystem');
    for I := 0 to Items.Count - 1 do begin
      Item := Items.ItemIndex(I);
      if Item.HypervisorPresent then Exit;
    end;
    Items := Service.ExecQuery('SELECT VirtualizationFirmwareEnabled FROM Win32_Processor');
    Result := False;
    for I := 0 to Items.Count - 1 do begin
      Item := Items.ItemIndex(I);
      if Item.VirtualizationFirmwareEnabled then Result := True;
    end;
  except
    Result := True;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := VirtualizationAvailable();
  if not Result then
    SuppressibleMsgBox('这台电脑没有开启硬件虚拟化（Intel VT-x / AMD-V），WSL 无法运行，橙域也就无法运行。' + #13#10#13#10 +
      '请在电脑的 BIOS/UEFI 设置中开启虚拟化后再安装。', mbCriticalError, MB_OK, IDOK);
end;

// The WSL from the Microsoft Store (wsl --version answers) is what runs Linux
// desktops (WSLg). Without it, wsl --install --no-distribution turns on the
// Windows features and installs it; that needs a restart.
function WslReady(): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\wsl.exe'), '--version', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

procedure EnableWsl();
var
  Code: Integer;
begin
  WizardForm.StatusLabel.Caption := '正在启用 WSL（需要联网下载，可能要几分钟）……';
  if not Exec(ExpandConstant('{sys}\wsl.exe'), '--install --no-distribution', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    SuppressibleMsgBox('启用 WSL 没有成功（代码 ' + IntToStr(Code) + '）。' + #13#10#13#10 +
      '可以稍后以管理员身份在命令提示符中运行 "wsl --install --no-distribution"，重启电脑后再打开橙域。', mbError, MB_OK, IDOK);
  RestartNeeded := True;
end;

// Before the files are copied: Setup asks NeedRestart right after copying,
// before ssPostInstall, so a restart decided any later would be lost.
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssInstall) and not WslReady() then
    EnableWsl();
end;

function NeedRestart(): Boolean;
begin
  Result := RestartNeeded;
end;

// Asked only once the uninstall is confirmed, just before the files go (the
// client is still there to do the removal). A silent uninstall keeps the data.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if (CurUninstallStep <> usUninstall) or UninstallSilent() then Exit;
  if MsgBox('是否同时删除本机的橙域数据？' + #13#10#13#10 +
      '会删除正在卸载的这个 Windows 账号的全部沙盒桌面（含其中的文件、浏览器资料和“下载”）、沙盒列表和保存的登录信息，不能撤销。' +
      '其他 Windows 账号的数据请在各自账号里用橙域登录界面的“删除本机全部数据…”删除。节点上的个人文件不受影响。' + #13#10#13#10 +
      '选“否”则保留这些数据，重新安装后可以继续使用。', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then Exit;
  if not Exec(ExpandConstant('{app}\OrangeSpace.exe'), '--remove-all-data', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    MsgBox('本机数据没有全部删除（代码 ' + IntToStr(Code) + '）。可以重新安装后在登录界面用“删除本机全部数据…”再试。', mbError, MB_OK);
end;
