# - customize xml
#   - network
#   - in/out
#   - download
# - customize a configuration file to drop for sandbox_init.ps1
# 
# - accept -Package vlc, sysinternals, totalcmd
# - start the sandbox
# - embed everything
# - shortcuts
# - wallpaper
# - no need of .cmd

# - use $Package to generate sandbox_init.ps1

Function Start-WindowsSandbox()
{
  Param(
    [Parameter()][Switch]$VGpu,
    [Parameter()][Switch]$Networking,
    [Parameter()][Switch]$MapDownload,
    [Parameter()][String[]]$Package
  )

  if($VGpu) { $VGpu = "Enable" } else { $VGpu = "Disable" }
  if($Networking) { $Networking = "Enable" } else { $Networking = "Disable" }
  if($MapDownload)
  {
    $ScriptPath = $MyInvocation.MyCommand.Path
    $DownloadPath = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    $DownloadPathXml = `
"<MappedFolder>
  <HostFolder>$DownloadPath</HostFolder>
  <ReadOnly>true</ReadOnly>
</MappedFolder>"
`
  }

  $WsbXml = `
"<Configuration>
<VGpu>$VGpu</VGpu>
<Networking>$Networking</Networking>
<MappedFolders>
    $DownloadPathXml
    <MappedFolder>
      <HostFolder>$ScriptPath\.wsb\ro</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$ScriptPath\.wsb\rw</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -ExecutionPolicy Unrestricted -Command `"Start powershell {-NoExit -File C:\Users\WDAGUtilityAccount\Desktop\ro\.wsbinit\init.ps1}`"</Command>
  </LogonCommand>
</Configuration>"
`

# Invoke-Item <path to .wsb>

}

Function Start-WindowsSandbox2 {
    [cmdletbinding(DefaultParameterSetName = "config")]
    [alias("wsb")]
    Param(
        [Parameter(ParameterSetName = "config")]
        [ValidateScript({Test-Path $_})]
        [string]$Configuration = "C:\scripts\WinSandBpx.wsb",
        [Parameter(ParameterSetName = "normal")]
        [switch]$NoSetup
    )

    Write-Verbose "Starting $($myinvocation.mycommand)"

    if ($NoSetup) {
        Write-Verbose "Launching default WindowsSandbox.exe"
        c:\windows\system32\WindowsSandbox.exe
    }
    else {
        Write-Verbose "Launching WindowsSandbox using configuration file $Configuration"
        Invoke-Item $Configuration
    }

    Write-Verbose "Ending $($myinvocation.mycommand)"
}
