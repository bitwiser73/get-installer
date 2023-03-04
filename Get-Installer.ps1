function Get-Installer()
{
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(HelpMessage="Software(s) name to download")][String[]]$Name,
        [Parameter(HelpMessage="Download directory")][String]$Destination = ".",
        [Parameter(HelpMessage="Install downloaded file")][Switch]$Install,
        [Parameter(HelpMessage="Show supported softwares")][Switch]$Show,
        [Parameter(HelpMessage="Enable parallel downloads")][Switch]$Parallel
    )

    $ConfigurationDirectory = "$ENV:USERPROFILE\.getinstaller"
    $BinariesDirectory = Join-Path $ConfigurationDirectory "bin"

    $Softwares = @(
        @{
            "Name" = "PowerToys"
            "Uri" = "https://github.com/microsoft/PowerToys"
            "Match" = "PowerToysSetup-[0-9\.]+-x64.exe"
            "Install" = { & $Installer /install /quiet }
        },
        @{
            "Name" = @("ripgrep", "rg")
            "Uri" = "https://github.com/BurntSushi/ripgrep"
            "Match" = "ripgrep-[0-9\.]+-i686-pc-windows-msvc.zip"
            "Install" = { Expand-ArchiveFile $Installer -Include @("rg.exe", "_rg.ps1") $BinariesDirectory }
        },
        @{
            "Name" = "jq"
            "Uri" = "https://github.com/stedolan/jq"
            "Match" = "jq-win64.exe"
            "Install" = { Copy-File $Installer $BinariesDirectory\jq.exe }
        },
        @{
            "Name" = "fd"
            "Uri" = "https://github.com/sharkdp/fd"
            "Match" = "fd-v[0-9\.]+-i686-pc-windows-msvc.zip"
            "Install" = { Expand-ArchiveFile $Installer -Include @("fd.exe", "_fd.ps1") $BinariesDirectory }
        },
        @{
            "Name" = "Nushell"
            "Uri" = "https://github.com/nushell/nushell"
            "Match" = "nu-[0-9\.]+-x86_64-pc-windows-msvc.zip"
            "Install" = { Expand-ArchiveFile $Installer $ENV:PROGRAMFILES\Nushell }
        },
        @{
            "Name" = "Ghidra"
            "Uri" = "https://github.com/NationalSecurityAgency/ghidra"
            "Match" = "ghidra_[0-9\.]+_PUBLIC_.*.zip"
            "Install" = { Expand-ArchiveFile $Installer -SubPath "ghidra*/*" $ENV:PROGRAMFILES\Ghidra }
        },
        @{
            "Name" = "Powershell"
            "Uri" = "https://github.com/PowerShell/PowerShell"
            "Match" = "Powershell-[0-9\.]+-win-x64.msi"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = "CMake"
            "Uri" = "https://github.com/Kitware/CMake"
            "Match" = "cmake-[0-9\.]+-windows-x86_64.msi"
            "Install" = {
                & $Installer /quiet
                Add-EnvPath $ENV:PROGRAMFILES\CMake\bin
            }
        },
        @{
            "Name" = "Git"
            "Uri" = "https://github.com/git-for-windows/git"
            "Match" = "Git-[0-9\.]+-64-bit.exe"
            "Install" = {
                & $Installer /silent
                Add-EnvPath $ENV:PROGRAMFILES\Git\usr\bin
            }
        },
        @{
            "Name" = "Wincompose"
            "Uri" = "https://github.com/samhocevar/wincompose"
            "Match" = "WinCompose-Setup-[0-9\.]+.exe"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = "Sharpkeys"
            "Uri" = "https://github.com/randyrants/sharpkeys"
            "Match" = "sharpkeys[0-9]+.msi"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = "Nextcloud"
            "Uri" = "https://github.com/nextcloud/desktop"
            "Match" = "Nextcloud-[0-9\.]+-x64.msi"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = @("ProcessHacker", "Process Hacker")
            "Uri" = "https://github.com/processhacker/processhacker"
            "Match" = "processhacker-[0-9\.]+-setup.exe"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = "KeepassXC"
            "Uri" = "https://github.com/keepassxreboot/keepassxc"
            "Match" = "KeePassXC-[0-9\.]+-Win64.msi"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = "Dependencies"
            "Uri" = "https://github.com/lucasg/Dependencies"
            "Match" = "Dependencies_x64_Release.zip"
            "Install" = {
                Expand-ArchiveFile -PassThru $Installer $ENV:PROGRAMFILES\Dependencies `
                    | Where-Object { $_.Name -in @("DependenciesGui.exe") } `
                    | ForEach-Object { Register-AppPath $_ }
            }
        },
        @{
            "Name" = "WinObjEx64"
            "Uri" = "https://github.com/hfiref0x/WinObjEx64"
            "Match" = "WinObjEx64_[0-9]+\.[0-9]+\.[0-9]+\.zip"
            "Install" = {
                Expand-ArchiveFile -PassThru $Installer $ENV:PROGRAMFILES\WinObjEx64 `
                    | Where-Object { $_.Name -eq "WinObjEx64.exe" } `
                    | ForEach-Object { Register-AppPath $_ }
            }
        },
        @{
            "Name" = "git-absorb"
            "Uri" = "https://github.com/tummychow/git-absorb"
            "Match" = "git-absorb-[0-9\.]+-x86_64-pc-windows-msvc.zip"
            "Install" = { Expand-ArchiveFile $Installer -Include "git-absorb.exe" $BinariesDirectory }
        },
        @{
            "Name" = "Zeal"
            "Uri" = "https://github.com/zealdocs/zeal"
            "Match" = "zeal-[0-9\.]+-windows-x64.msi"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = @("vscode", "Visual Studio Code", "code")
            "Uri" = "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = "HxD"
            "Uri" = "https://mh-nexus.de/downloads/HxDSetup.zip"
            "Install" = {
                $Temp = New-TemporaryDirectory
                Expand-ArchiveFile $Installer $Temp
                & $Temp/HxDSetup.exe /silent
            }
        },
        @{
            "Name" = @("Sysinternals", "SysinternalsSuite", "Sysinternals Suite")
            "Uri" = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
            "Install" = {
                Expand-ArchiveFile -PassThru $Installer $ENV:PROGRAMFILES\SysinternalsSuite `
                    | Where-Object { $_.Name -in @("procexp.exe", "procmon.exe", "autoruns.exe") } `
                    | ForEach-Object { Register-AppPath $_ }
                }
        },
        @{
            "Name" = "Element"
            "Uri" = "https://packages.riot.im/desktop/install/win32/x64/Element%20Setup.exe"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = @("ExplorerSuite", "Explorer Suite")
            "Uri" = "https://ntcore.com/files/ExplorerSuite.exe"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = "Rust"
            "Uri" = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
        },
        @{
            "Name" = "p4merge"
            "Uri" = "https://www.perforce.com/downloads/perforce/r22.1/bin.ntx64/p4vinst64.msi"
            "Warning" = "A more recent version could be available, check: https://www.perforce.com/downloads/visual-merge-tool"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = @("Sublime Text", "subl")
            "Uri" = "https://www.sublimetext.com/download_thanks?target=win-x64"
            "Match" = "(https://download.sublimetext.com/sublime_text_build_[0-9\.]+_x64_setup.exe)"
            "Install" = { & $Installer /silent }
        },
        @{
            "Name" = @("Python3", "Python 3")
            "Uri" = "https://www.python.org/downloads/"
            "Match" = "(https://www.python.org/ftp/python/[0-9\.]+/python-[0-9\.]+-amd64\.exe)"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = @("Total Commander", "TotalCommander", "tcmd", "totalcmd")
            "Uri" = "https://www.ghisler.com/download.htm"
            "Match" = "(https://.*tcmd.*x64\.exe)"
            "Install" = { & $Installer /AHMGDU }
        },
        @{
            "Name" = @("IDA", "IDA Free", "IDA-Free")
            "Uri" = "https://hex-rays.com/ida-free/"
            "Match" = "(https://.*idafree[0-9]+_windows.exe)"
            "Install" = { & $Installer --mode unattended }
        },
        @{
            "Name" = "x64dbg"
            "Uri" = "https://github.com/x64dbg/x64dbg"
            "Match" = "(snapshot_.*\.zip)"
            "Install" = { Expand-ArchiveFile $Installer -SubPath "release\*" $ENV:PROGRAMFILES\x64dbg }
        },
        @{
            "Name" = "wireshark"
            "Uri" = "https://www.wireshark.org/download.html"
            "Match" = "(https://.*dl.wireshark.org/win64/Wireshark-win64-[0-9]+\.[0-9]+\.[0-9]+\.exe)"
            "Install" = { Write-Warning "Install manually because of npcap requirement: $Installer" }
        },
        @{
            "Name" = @("7zip", "7-zip", "7z")
            "Uri" = "https://www.7-zip.org/download.html"
            "Match" = "href.*`"(.*/7z[0-9]+-x64\.msi)"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = @("Kerberos", "kfw", "Kerberos for Windows")
            "Uri" = "https://web.mit.edu/kerberos/dist/index.html"
            "Match" = "(kfw/[0-9\.]+/kfw-[0-9\.]+-amd64\.msi)"
            "Install" = { & $Installer /quiet }
        },
        @{
            "Name" = "windirstat"
            "Uri" = "https://windirstat.mirror.wearetriple.com//wds_current_setup.exe"
            "Install" = { & $Installer /S }
        },
        @{
            "Name" = "XMind"
            "Uri" = "https://www.xmind.app/zen/download/win64"
            "FileName" = "XMind.exe"
            "Install" = { & $Installer /allusers /S }
        },
        @{
            "Name" = "Firefox"
            "Uri" = "https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US&_gl=1"
            "Install" = { & $Installer /quiet }
        }
    )

    function Test-IsAdministrator
    {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function New-TemporaryDirectory
    {
        $Parent = [System.IO.Path]::GetTempPath()
        [string] $Name = [System.Guid]::NewGuid()
        [System.IO.DirectoryInfo]$Temp = New-Item -ItemType Directory -Path (Join-Path $Parent $Name) -ErrorAction Stop
        return $Temp
    }

    function Copy-File
    {
        Param(
            [Parameter(Mandatory, ValueFromPipeline = $true)][System.IO.FileInfo]$Path,
            [Parameter(Mandatory)]$Destination
        )

        Begin
        {
            $OutputDirectory = $Destination -Replace "/", "\"
            if (-not $OutputDirectory.EndsWith("\"))
            {
                $OutputDirectory = $OutputDirectory.Remove($Destination.LastIndexOf("\"))
            }

            New-Item -ItemType Directory -ErrorAction SilentlyContinue $OutputDirectory | Out-Null
        }

        Process
        {
            foreach ($File in $Path)
            {
                Write-Verbose "'$Path' -> '$Destination'"
                Copy-Item $Path.FullName -Destination $Destination
            }
        }
    }

    function Expand-ArchiveFile
    {
        Param(
            [Parameter(Mandatory)]$InputFile,
            [Parameter(Mandatory)]$Destination,
            [Parameter()]$SubPath,
            [Parameter()][String[]]$Include,
            [Parameter()][Switch]$PassThru
        )

        Write-Verbose "Extracting '$InputFile' to '$Destination'"

        # A temporary directory is required because 'ExtractToDirectory' would fail
        # if files already exists. Removing target directory would not be safe.
        $Temp = New-TemporaryDirectory -ErrorAction Stop
        if (-not $Temp)
        {
            Write-Error "Failed to create temporary directory"
            return
        }

        # Note: newer versions have 'overwrite' parameter
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($InputFile, $Temp)

        if ($Include -or $SubPath)
        {
            $TempExtract = $Temp
            $Temp = New-TemporaryDirectory
            if ($SubPath)
            {
                $TempExtract = Join-Path $TempExtract $SubPath
            }

            Get-ChildItem -Path $TempExtract -Include:$Include -Recurse | Move-Item -Destination $Temp
        }

        # For compatibility do not use '[System.IO.Path]::GetRelativePath($Temp, $_)'
        $Files = Get-ChildItem -Recurse -File $Temp `
            | Foreach-Object { $_.FullName.SubString($Temp.FullName.Length + 1) } `
            | ForEach-Object { [System.IO.FileInfo]$(Join-Path $Destination $_) }

        # Move files to output directory
        if (-not $(Test-Path $Destination))
        {
            New-Item -ItemType Container $Destination | Out-Null
        }

        Move-Item -Force "$Temp/*" "$Destination" | Write-Verbose

        ForEach ($File in $Files)
        {
            Write-Verbose $File
            if (-not $(Test-Path $File))
            {
                Write-Error "Failed to extract: $File"
            }
        }

        if ($PassThru)
        {
            return $Files
        }
    }

    function Register-AppPath
    {
        Param(
            [Parameter(Mandatory)]$Path,
            [ValidateSet('Machine', 'User')][String]$Target
        )

        if (-not $Target)
        {
            if ($(Test-IsAdministrator))
            {
                $Hive = "HKLM"
            }
            else
            {
                $Hive = "HKCU"
            }
        }
        else
        {
            if ($Target -eq "Machine")
            {
                $Hive = "HKLM"
            }
            else
            {
                $Hive = "HKCU"
            }
        }

        $Leaf = Split-Path -Leaf $Path
        $Key = "$($Hive):SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$Leaf"
        New-Item -Force -Path $Key -Value $Path | Out-Null
        New-ItemProperty -Path $Key -Name "Path" -Value $Path | Out-Null
    }

    function Add-EnvPath
    {
        Param(
            [Parameter(Mandatory)][String]$Path,
            [ValidateSet('Machine', 'User')][String]$Target
        )

        if (-not $Target)
        {
            if ($(Test-IsAdministrator))
            {
                $Target = "Machine"
            }
            else
            {
                $Target = "User"
            }
        }

        $PathValues = [Environment]::GetEnvironmentVariable('Path', $Target) -split ';'
        if ($PathValues -notcontains $Path)
        {
            [Environment]::SetEnvironmentVariable('Path', $($PathValues + $Path) -join ';', $Target)
        }
    }

    function Get-InstallerFromGithub
    {
        Param([Parameter(Mandatory)]$Software)

        $Repository = $Software.Uri.Substring("https://github.com/".Length)
        $ReleasesApi = "https://api.github.com/repos/$Repository/releases"

        # Add -UseBasicParsing for compatibility with Powershell 2 vanilla configuration
        $Request = Invoke-WebRequest -UseBasicParsing ${ReleasesApi} | ConvertFrom-Json

        # Get the most recent tag
        $TagName = $Request `
            | Where-Object { $_.tag_name -NotMatch ".*rc.*|.*beta.*|.*preview.*" } `
            | Sort-Object -Property tag_name -Descending `
            | Select-Object -First 1 -ExpandProperty tag_name

        # Get the assets of the most recent tag
        $Assets = $Request `
            | Where-Object { $_.tag_name -eq $TagName } `
            | Select-Object -ExpandProperty assets

        # Get the first asset matching specified filename regex
        $Asset = $Assets `
            | Where-Object { $_.name -match $Software.Match } `
            | Select-Object -First 1

        $Software.FileName = $Asset.name
        $Software.DownloadUrl = $Asset.browser_download_url
        return $Software
    }

    # rest api or rss stream only give the .../download url without resolving the mirror
    # curl -qsL "https://sourceforge.net/projects/x64dbg/best_release.json"
    function Get-InstallerFromSourceForge
    {
        Param([Parameter(Mandatory)]$Software)

        Write-Verbose "$($Software.Name[0]): Sourceforge snapshot: $Uri"

        $Snapshots = Invoke-WebRequest -UseBasicParsing $Uri
        $Snapshot = ($Snapshots.Links.href -match "https://sourceforge.net/projects/[^/]+/files/.*/download")[0]
        $Request = Invoke-WebRequest -UseBasicParsing $Snapshot

        # /settings/mirror_choices?projectname=x64dbg&amp;filename=snapshots/snapshot_2022-08-08_23-56.zip&amp;selected=netcologne
        [String]$Request.Links.href -match "/settings/mirror_choices\?projectname=(.*)&amp;filename=snapshots/(.*)&amp;selected=([^\s]+)" | Out-Null
        $Server, $Filename, $Name = $Matches.Values | Select-Object -First 3

        $Software.FileName = "$($Name)_$($Filename)"
        $Software.DownloadUrl = "https://$Server.dl.sourceforge.net/project/$Name/snapshots/$Filename"
        return $Software
    }

    function Get-InstallerFromLink
    {
        Param([Parameter(Mandatory)]$Software)

        if ($Software.Match)
        {
            $Request = Invoke-WebRequest -UseBasicParsing $Software.Uri
            if (-not ($Request.RawContent -match $Software.Match))
            {
                Write-Error "$($Software.Name[0]): Failed to retrieve matching value for regex"
                continue
            }

            $Match = $Matches[$Matches.Count - 1]
            if ($Match.StartsWith("http"))
            {
                $Uri = $Match
            }
            else
            {
                # Build from relative link a complete uri
                $Uri = $Software.Uri.SubString(0, $Software.Uri.LastIndexOf("/")) + "/" + $Match
            }
        }

        Write-Verbose "  Uri: $Uri"
        $Request = Invoke-WebRequest -UseBasicParsing -Method HEAD $Uri
        Write-Verbose "  Content-Type: $($Request.Headers['Content-Type'])"
        Write-Verbose "  Content-Disposition: $($Request.Headers['Content-Disposition'])"

        # Try to find a friendly file name
        if ($Software.FileName)
        {
            $Filename = $Software.FileName
            Write-Verbose "  => Using filename: $Filename (from software's FileName)"
        }
        elseif ([String]$Request.Headers['Content-Disposition'] -match "filename=`"(.*)`"")
        {
            $Filename = $Matches[1]
            Write-Verbose "  => Using filename: $Filename (from 'Content-Disposition')"
        }
        elseif ($Uri -match ".*\.[a-zA-Z0-9]+$")
        {
            # Compatibility issue: $Filename = [System.Web.HttpUtility]::UrlDecode($(Split-Path -Leaf $Uri))
            $Filename = [uri]::UnEscapeDataString($(Split-Path -Leaf $Uri))
            Write-Verbose "  => Using filename: $Filename (from software's link)"
        }
        else
        {
            $Extensions = @{
                "application/x-msi" = ".msi"
                "application/x-msdos-program" = ".exe"
                "application/zip" = ".zip"
                "application/x-zip-compressed" = ".zip"
            }

            $Extension = $Extensions[[String]$Request.Headers['Content-Type']]
            $Filename = "$($Software.Name[0])$Extension"

            Write-Verbose "  => Using filename: $Filename (from software's name)"
        }

        $Software.FileName = $Filename -replace " ","_"
        $Software.DownloadUrl = $Uri
        return $Software
    }

    function Install-Software($Software)
    {
        # Set 'Installer' which is expected from user's ScriptBlock
        $Installer = $Software.Path
        Write-Host "$($Software.Name[0]): install '$Installer'"

        if ($Software.Install -is [ScriptBlock])
        {
            Invoke-Command -ScriptBlock $Software.Install
        }
        else
        {
            Write-Error "Unsupported install method"
        }
    }

    ###
    ### Main
    ###

    $ErrorActionPreference = 'Stop'

    # Do not display progress because it will make Invoke-Webrequest very slow
    $ProgressPreference = 'SilentlyContinue'

    if (-not $Name)
    {
        if (-not $Show)
        {
            Write-Error "Missing parameter '-Name'"
            return
        }
    }
    elseif ($Name -eq '*')
    {
        $Name = $null
    }

    if (-not $(Test-Path $Destination))
    {
        New-Item -ItemType Directory $Destination
    }

    if ($Install)
    {
        Add-EnvPath $BinariesDirectory
    }

    # Make sure $Software.Name is always an array
    foreach ($Software in $Softwares)
    {
        if ($Software.Name -isnot [Array])
        {
            $Software.Name = @($Software.Name)
        }
    }

    if ($Show)
    {
        $Found = @()
        foreach ($Software in $Softwares)
        {
            # TODO: accept wildcard
            if ($Name -and -not $($Software.Name | Where-Object {$Name -contains $_}))
            {
                continue
            }

            $Found += $Software
        }

        $Found | Select-Object -Property Name, Uri | Sort-Object -Property Name
        return
    }

    $Downloads = @()
    foreach ($Software in $Softwares)
    {
        if ($Name -and -not $($Software.Name | Where-Object {$Name -contains $_}))
        {
            continue
        }

        Write-Verbose "$($Software.Name[0]): $($Software.Uri)"

        if ($Software.Warning)
        {
            Write-Warning "$($Software.Name[0]): $($Software.Warning)"
        }

        if ($Software.Uri -is [ScriptBlock])
        {
            $Uri = Invoke-Command -ScriptBlock $Software.Uri
        }
        else
        {
            $Uri = $Software.Uri
        }

        if ($Uri -match "https://sourceforge.net/projects/[^/]+/files/snapshots")
        {
            $Downloads += Get-InstallerFromSourceForge $Software
        }
        elseif ($Uri.StartsWith("https://github.com/"))
        {
            $Downloads += Get-InstallerFromGithub $Software
        }
        else
        {
            $Downloads += Get-InstallerFromLink $Software
        }

        Write-Verbose "Download url: $($Software.DownloadUrl), filename: $($Software.FileName)"
    }

    foreach ($Software in $Downloads)
    {
        $Out = Join-Path $(Resolve-Path $Destination) $($Software.FileName -replace " ","_")
        Write-Host "$($Software.Name[0]): $($Software.DownloadUrl) -> `"$Out`""

        if (-not $WhatIfPreference)
        {
            if (Test-Path $Out)
            {
                Write-Warning "$($Software.Name[0]): use existing file '$Out'"
                $Software["Path"] = $Out
            }
            else
            {
                if (-Not $Parallel)
                {
                    Invoke-WebRequest -UseBasicParsing $Software.DownloadUrl -Out $Out
                    $Software["Path"] = $Out
                }
                else
                {
                    # FIXME: any Ctrl+C would break without removing the jobs
                    $Software["Path"] = $Out
                    $Source = $Software.DownloadUrl
                    Start-Job -Name "GET $($Software.Name[0].ToUpper())" {
                        Invoke-WebRequest -UseBasicParsing $using:Source -Out $using:Out
                    }
                }
            }
        }
    }

    if ($Parallel)
    {
        Get-Job | Wait-Job
    }

    if (-not $WhatIfPreference -and $Install)
    {
        if (-not $(Test-IsAdministrator))
        {
            Write-Warning "Some installer may not work without an elevated account"
        }

        foreach ($Software in $Downloads)
        {
            if ($Software.Install)
            {
                Write-Verbose "$($Software.Name[0]): Install $($Software.Path)"
                Install-Software $Software
            }
        }
    }

    foreach ($NameEntry in $Name)
    {
        if (-not $($Downloads | Where-Object { $_.Name -like $NameEntry }))
        {
            Write-Error "Unknown application: $NameEntry"
        }
    }
}

If ($MyInvocation.InvocationName -ne ".")
{
    Get-Installer @args
}
