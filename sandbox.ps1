# - customize xml
#   - network
#   - in/out
#   - download
# - customize a configuration file to drop for sandbox_init.ps1
# 
# - accept -Package vlc, sysinternals, totalcmd
# - start the sandbox
# - embed everything

<Configuration>
<VGpu>Disable</VGpu>
<Networking>Enable</Networking>
<MappedFolders>
   <MappedFolder>
     <HostFolder>c:\Users\user\Downloads</HostFolder>
     <ReadOnly>true</ReadOnly>
   </MappedFolder>
   <MappedFolder>
     <HostFolder>c:\Users\user\Sandbox\ReadOnly</HostFolder>
     <ReadOnly>true</ReadOnly>
   </MappedFolder>
   <MappedFolder>
     <HostFolder>c:\Users\user\Sandbox\Out</HostFolder>
     <ReadOnly>false</ReadOnly>
   </MappedFolder>
</MappedFolders>
<LogonCommand>
   <Command>explorer.exe C:\users\WDAGUtilityAccount\Desktop\Downloads</Command>
</LogonCommand>
</Configuration>

Function Start-WindowsSandbox {
    [cmdletbinding(DefaultParameterSetName = "config")]
    [alias("wsb")]
    Param(
        [Parameter(ParameterSetName = "config")]
        [ValidateScript({Test-Path $_})]
        [string]$Configuration = "C:\scripts\WinSandBx.wsb",
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
