# - winget
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

Function Start-WindowsSandbox()
{
    Param(
        [Parameter()][Switch]$VGpu,
        [Parameter()][Switch]$Networking,
        [Parameter()][Switch]$MapDownload,
        [Parameter()][String[]]$Package
    )

    $ScriptPath = $MyInvocation.MyCommand.Path

    if($VGpu) { $VGpuXml = "Enable" } else { $VGpuXml = "Disable" }
    if($Networking) { $NetworkingXml = "Enable" } else { $NetworkingXml = "Disable" }
    if($MapDownload)
    {
        $DownloadPath = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
        $DownloadPathXml = `
"
<MappedFolder>
  <HostFolder>$DownloadPath</HostFolder>
  <ReadOnly>true</ReadOnly>
</MappedFolder>"
    }

    $WindowsSandbox = "WindowsSandbox"
    $Temp = Join-Path $ENV:TEMP $WindowsSandbox
    New-Item -ItemType Directory -Force $Temp | Out-Null

    $SandboxXml = `
"<Configuration>
  <VGpu>$VGpuXml</VGpu>
  <Networking>$NetworkingXml</Networking>
  <MappedFolders>
    $DownloadPathXml
    <MappedFolder>
      <HostFolder>$Temp</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -ExecutionPolicy Unrestricted -Command `"Start powershell {-NoExit -File C:\Users\WDAGUtilityAccount\Desktop\$WindowsSandbox\Init.ps1}`"</Command>
  </LogonCommand>
</Configuration>"
`

    $Configuration = Join-Path $Temp "Sandbox.wsb"
    $SandboxXml | Out-File -Force $Configuration
    Invoke-Item $Configuration
}
