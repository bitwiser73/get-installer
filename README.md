# Get-Installer
All-in-one lighweight script to download and install last version of softwares.

## Usage
Install git and visual studio code
```
> Get-Installer.ps1 git, code -install
Git: https://github.com/git-for-windows/git/releases/download/v2.38.0.windows.1/Git-2.38.0-64-bit.exe -> "C:\Foo\Git-2.38.0-64-bit.exe"
vscode: https://code.visualstudio.com/sha/download?build=stable&os=win32-x64 -> "C:\Foo\VSCodeSetup-x64-1.72.2.exe"
Git: install 'C:\Foo\Git-2.38.0-64-bit.exe'
vscode: install 'C:\Foo\VSCodeSetup-x64-1.72.2.exe'
```

## Features
- One file with few line of codes
- Compatible with >= Windows Seven
- Get directly latest software from authors
- Download installers and eventually install and configure them (PATH, ...)
- Easy to review or add new software (support Github API, direct links and webpage analysis as software)
- Create a repository archive with many installers for later use (offline installations...)

## Supported installers

```
> Get-Installer.ps1 -show

Name                                                  Uri
----                                                  ---
{7zip, 7-zip, 7z}                                     https://www.7-zip.org/download.html
{CMake}                                               https://github.com/Kitware/CMake
{Dependencies}                                        https://github.com/lucasg/Dependencies
{Element}                                             https://packages.riot.im/desktop/install/win32/x64/Element%20Setup.exe
{ExplorerSuite, Explorer Suite}                       https://ntcore.com/files/ExplorerSuite.exe
{fd}                                                  https://github.com/sharkdp/fd
{Firefox}                                             https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en…
{Ghidra}                                              https://github.com/NationalSecurityAgency/ghidra
{git}                                                 https://github.com/git-for-windows/git
{git-absorb}                                          https://github.com/tummychow/git-absorb
{GitHub Desktop}                                      https://central.github.com/deployments/desktop/desktop/latest/win32?format=msi
{HxD}                                                 https://mh-nexus.de/downloads/HxDSetup.zip
{IDA, IDA Free, IDA-Free}                             https://hex-rays.com/ida-free/
{ImHex}                                               https://github.com/WerWolv/ImHex
{Inkscape}                                            …
{jq}                                                  https://github.com/stedolan/jq
{KeepassXC}                                           https://github.com/keepassxreboot/keepassxc
{Kerberos, kfw, Kerberos for Windows}                 https://web.mit.edu/kerberos/dist/index.html
{Nextcloud}                                           https://github.com/nextcloud/desktop
{Nushell, nu}                                         https://github.com/nushell/nushell
{OSFMount}                                            https://www.osforensics.com/downloads/osfmount.exe
{p4merge}                                             https://www.perforce.com/downloads/perforce/r22.1/bin.ntx64/p4vinst64.msi
{posh-git}                                            https://github.com/dahlbyk/posh-git
{Powershell, pwsh}                                    https://github.com/PowerShell/PowerShell
{PowerToys}                                           https://github.com/microsoft/PowerToys
{ProcessHacker, Process Hacker}                       https://github.com/processhacker/processhacker
{Python3, Python 3}                                   https://www.python.org/downloads/
{ripgrep, rg}                                         https://github.com/BurntSushi/ripgrep
{Rufus}                                               https://github.com/pbatard/rufus
{Rust}                                                https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.e…
{Sublime Text, subl}                                  https://www.sublimetext.com/download_thanks?target=win-x64
{Sysinternals, SysinternalsSuite, Sysinternals Suite} https://download.sysinternals.com/files/SysinternalsSuite.zip
{System Informer, systeminformer, si}                 https://github.com/winsiderss/si-builds
{Total Commander, TotalCommander, tcmd, totalcmd}     https://www.ghisler.com/download.htm
{vcredist, vcredist17, vcredist17_x64}                https://aka.ms/vs/17/release/vc_redist.x64.exe
{Visual Studio Code, vscode, code}                    https://code.visualstudio.com/sha/download?build=stable&os=win32-x64
{vlc, videolan}                                       https://mirrors.ircam.fr/pub/videolan/vlc/last/win64/
{Wincompose}                                          https://github.com/samhocevar/wincompose
{WinDirStat}                                          https://windirstat.mirror.wearetriple.com/wds_current_setup.exe
{WinObjEx64}                                          https://github.com/hfiref0x/WinObjEx64
{Wireshark}                                           https://www.wireshark.org/download.html
{x64dbg}                                              https://github.com/x64dbg/x64dbg
{XMind}                                               https://www.xmind.app/zen/download/win64
{yara}                                                https://github.com/VirusTotal/yara
{Zeal}                                                https://github.com/zealdocs/zeal
```

## Built-in configuration example

Part of *Get-Installer.ps1*
```
    $Softwares = @(
        @{
            "Name" = "Git"
            "Uri" = "https://github.com/git-for-windows/git"
            "Match" = "Git-[0-9\.]+-64-bit.exe"
            "Install" = { Start-Process -Wait $Installer /silent }
            "Configure" = { Add-EnvPath $ENV:PROGRAMFILES\Git\usr\bin }
        },
        @{
            "Name" = @("vscode", "Visual Studio Code", "code")
            "Uri" = "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64"
            "Install" = { Start-Process -Wait $Installer /silent }
        },
        @{
            "Name" = @("Sysinternals", "SysinternalsSuite", "Sysinternals Suite")
            "Uri" = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
            "Install" = { Expand-ArchiveFile -PassThru $Installer $ENV:PROGRAMFILES\SysinternalsSuite }
            "Configure" = {
                $InstallOutput `
                  | Where-Object { $_.Name -in @("procexp.exe", "procmon.exe", "autoruns.exe") } `
                  | ForEach-Object { Register-AppPath $_ }
            }
        },
        @{
            "Name" = @("Python3", "Python 3")
            "Uri" = "https://www.python.org/downloads/"
            "Match" = "(https://www.python.org/ftp/python/[0-9\.]+/python-[0-9\.]+-amd64\.exe)"
            "Install" = { Start-Process -Wait $Installer /quiet }
        }
    )
```

## Create and use repository archive
For some situations, like when there is no internet connection available, you can prepare a repository archive that will store selected installers for later use.

```ps1
# Prepare an archive that stores rg, fd, jq installers and a manifest
.\Get-Installer.ps1 rg, fd, jq -Destination c:\users\fb\Desktop\installers.zip

ripgrep: https://github.com/BurntSushi/ripgrep/releases/download/13.0.0/ripgrep-13.0.0-i686-pc-windows-msvc.zip -> "C:\Users\fb\AppData\Local\Temp\99ac115b-7294-4af6-95ee-2b49522ee307\ripgrep-13.0.0-i686-pc-windows-msvc.zip"
fd: https://github.com/sharkdp/fd/releases/download/v8.7.0/fd-v8.7.0-i686-pc-windows-msvc.zip -> "C:\Users\fb\AppData\Local\Temp\99ac115b-7294-4af6-95ee-2b49522ee307\fd-v8.7.0-i686-pc-windows-msvc.zip"
jq: https://github.com/jqlang/jq/releases/download/jq-1.6/jq-win64.exe -> "C:\Users\fb\AppData\Local\Temp\99ac115b-7294-4af6-95ee-2b49522ee307\jq-win64.exe"
New repository: c:\users\fb\Desktop\installers.zip


# Install rg from the repository archive
.\Get-Installer.ps1 rg -install -Repository e:\installers.zip

ripgrep: zip://e:\installers.zip\ripgrep-13.0.0-i686-pc-windows-msvc.zip -> "C:\Users\joe\Downloads\ripgrep-13.0.0-i686-pc-windows-msvc.zip"
ripgrep: install 'C:\Users\joe\Downloads\ripgrep-13.0.0-i686-pc-windows-msvc.zip'
ripgrep: configure 'C:\Users\joe\Downloads\ripgrep-13.0.0-i686-pc-windows-msvc.zip'
```
