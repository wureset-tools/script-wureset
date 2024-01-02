## ==================================================================================
## NAME:	Reset Windows Update Tool.
## DESCRIPTION:	This script reset the Windows Update Components.
## AUTHOR:	Manuel Gil.
## ==================================================================================
## PowerShell Conversion by Neil Haagensen
## Verson 0.0.1 2023-12-14 - DO NOT RUN! Still has unconverted DOS BAT code.
## Started conversion 
## Verson 0.0.2 2023-12-26 - DO NOT RUN! Still has unconverted DOS BAT code.
## Refactored all anonymous functions into proper PS functions
## Verson 0.0.3 2023-12-28 - DO NOT RUN! Still has unconverted DOS BAT code.
## Solved sd.exe problem continued refactoring code.
## Version 0.0.4 2023-12-28 - Reached EoF
## Corrected error in self-elevation
## Main Menu is now live.
## Version 1.0 2023-12-29
## Corrected lingering incorrect calls to Print function
## Corrected typos in regedit function
## Fixed commands for gpupdate, chkdsk, and restart functions
## TODO: 
## ===============================================================================


## Set console.
## void mode();
## /************************************************************************************/

#:mode
#$SetMode = {
function initialize {
	#Set-PSDebug -Off
	$host.ui.RawUI.WindowTitle = "Reset Windows Update Tool."
    $Name = $null
    $Family = $null
    $currentDate = Get-Date -Format "yyyy-MM-dd"
	#mode con cols=90 lines=36
	#color 17
	clear
    GetValues
	#goto getValues
}

## /************************************************************************************/


## Print Top Text.
##		@param - text = the text to print (%*).
## void print(string text);
## /*************************************************************************************/

#:print
function PrintTop {
    param(
        [string]$Title
    )
	clear
	Write-Host "`n$Name [Version: $Version]"
    Write-Host "Reset Windows Update Tool."
    Write-Host "`n`n$Title"
}

## /*************************************************************************************/


## Add Value in the Registry.
##		@param - key = the key or entry to be added (%~1).
##				value = the value to be added under the selected key (%~2).
##				type = the type for the registry entry (%~3).
##				data = the data for the new registry entry (%~4).
## void addReg(string key, string value, string type, string data);
## /*************************************************************************************/

#:addReg
function AddRegistryValue {
    param (
        [string]$Key,
        [string]$Value,
        [string]$Type,
        [string]$Data
    )
	reg add "$Key" /v "$Value" /t "$Type" /d "$Data" /f
}
## /*************************************************************************************/


## Load the system values.
## void getValues();
## /************************************************************************************/
#:getValues
function GetValues {
#	for /f "tokens=4 delims=[] " %%a in ('ver') do set version=%%a
    $Version = systeminfo | findstr /B /C:"OS Version"

	if ($Version -match "6.1.7600") {
		## Name: "Microsoft Windows 7"
		$Name="Microsoft Windows 7"
		## Family: Windows 7
		$Family=7
		## Compatibility: No
        $Allow = $false
	} elseif ($Version -match "6.1.7601") {
		## Name: "Microsoft Windows 7 SP1"
		$Name="Microsoft Windows 7 SP1"
		## Family: Windows 7
		$Family=7
		## Compatibility: No
        $Allow = $false
	} elseif ($version -match "6.2.9200") {
		## Name: "Microsoft Windows 8"
		$Name="Microsoft Windows 8"
		## Family: Windows 8
		$Family=8
		## Compatibility: Yes
		$Allow = $true
	} elseif ($Version -match "6.3.9200") {
		## Name: "Microsoft Windows 8.1"
		$Name="Microsoft Windows 8.1"
		## Family: Windows 8
		$Family=8
		## Compatibility: Yes
		$Allow = $true
	} elseif ($Version -match "6.3.9600") {
		## Name: "Microsoft Windows 8.1 Update 1"
		$Name="Microsoft Windows 8.1 Update 1"
		## Family: Windows 8
		$Family=8
		## Compatibility: Yes
		$Allow=$true
	} elseif ($Version -match "10.0.1") {
		## Name: "Microsoft Windows 10"
		$Name="Microsoft Windows 10"
		## Family: Windows 10
		$Family = 10
		## Compatibility: Yes
        $Allow = $true
	} elseif ($Version -match "10.0.2") {
		## Name: "Microsoft Windows 11"
		$Name="Microsoft Windows 11"
		## Family: Windows 11
		$Family=11
		## Compatibility: Yes
        $Allow = $true
    } else {
		## Name: "Unknown"
		$Name=Unknown
		## Family: Undetermined
        $Family=0
		## Compatibility: No
		$Allow = $false
	}

	PrintTop -Title "$Name detected..."

	if ($Allow) {
        AdminAuthz
    } else {

	    Write-Host "Sorry, this Operating System is not compatible with this tool."
        Write-Host "An error occurred while attempting to verify your system."
	    Write-Host "You may be using a business or test version of Windows."
	    Pause -Message "Verify that your system has the latest security updates."
        Close   
    }
}
## /************************************************************************************/


## Checking for Administrator elevation.
## void permission();
## /************************************************************************************/
##:permission
function AdminAuthz {
    PrintTop -Title "Checking for Administrator Privileges."
    if (!
        #current role
        (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
        #is admin?
        )).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    ) {
           
        #elevate script and exit current non-elevated runtime
        Write-Host "You are not running as Administrator."
        Write-Host "This tool cannot do it's job without elevation."
        Pause -Message "Script will invoke the User Account Control and 
        attempt to re-run with administrator privileges."
        #Create a new Elevated process to Start PowerShell
        $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
        # Specify the current script path and name as a parameter
        $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
        #Set the Process to elevated
        $ElevatedProcess.Verb = "runas"
 
        #Start the new elevated process
        [System.Diagnostics.Process]::Start($ElevatedProcess)
 
        #Exit from the current, unelevated, process
        Exit
     }
    Terms
}
## /************************************************************************************/


## Terms.
## void terms();
## /*************************************************************************************/
#:terms
function Terms {
    $Title = ""
    $Prompt = "Do you wish to continue?"
    $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
    $Default = 1
    PrintTop -Title "Terms and Conditions of Use."
    Write-Host "`nThe methods inside this tool modify files and registry settings."
    Write-Host "`nWhile this tool has been tested and usually to works, we assume no"
    Write-Host "liability for the use of this tool."
    Write-Host "`nThis tool is provided without warranty. Any damage caused to your system"
    Write-Host "is your own responsibility."
    Write-Host "`nScript files are almost always flagged by anti-virus, feel free"
    Write-Host "to review the code if you're unsure."

#	choice /c YN /n /m "Do you want to continue with this process? (Y/N) "
    $Decision = $Host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
	if ($Decision -eq 0) {
		Menu
	} else {
        exit
	}
}
<# /*************************************************************************************/


:: Menu of tool.
:: void menu();
/*************************************************************************************/ #>
##:menu
##	call :print This tool reset the Windows Update Components.
function menu {
    do {
        PrintTop -Title "Main Menu"
	    Write-Host "
    1. Opens the system protection.
    2. Resets the Windows Update Components.
    3. Deletes the temporary files in Windows.
    4. Opens the Internet Explorer options.
    5. Runs Chkdsk on the Windows partition.
    6. Runs the System File Checker tool.
    7. Scans the image for component store corruption.
    8. Checks whether the image has been flagged as corrupted.
    9. Performs repair operations automatically.
    10. Cleans up the superseded components.
    11. Deletes any incorrect registry values.
    12. Repairs/Resets Winsock settings.
    13. Forces Group Policy Update.
    14. Searches Windows updates.
    15. Resets the Windows Store.
    16. Finds the Windows Product Key.
    17. Explores other local solutions.
    18. Explores other online solutions.
    19. Downloads the Diagnostic Tools.
    20. Restarts your PC.
	
	                                        ?. Help.    0. Close."

	    $UserOption = Read-Host("Select an option")
        switch ($UserOption) {
            0 {
                Close
            }
            1 {
            	SysProtection
            }
            2 {
                Components            
            }
            3 {
                temp
            }
            4 {
                iOptions
            }
            5 {
                chkdsk
            }
            6 {
                sfc
            }
            7 {
                dism1
            }
            8 {
                dism2
            }
            9 {
                dism3
            }
            10 {
                dism4
            }
            11 {
                regedit
            }
            12 {
                winsock
            }
            13 {
                gpupdate
            }
            14 {
                updates
            }
            15 {
                wsreset
            }
            16 {
                productKey
            }
            17 {
                local
            }
            18 {
                online
            }
            19 {
                diagnostic
            }
            20 {
                restart
            }
            '?' {
                help
            }
            default {
                Pause -Message "Invalid Option"
            }
#		echo.
#		echo.Invalid option.
#		echo.
#		echo.Press any key to continue . . .
#		pause>nul
#	)
        }
    } while($UserOption -ne 0)
}
## /*************************************************************************************/

## Pause function
## void Pause(string Message);
## /*************************************************************************************/
function Pause {
    param (
        $Message
    )
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$Message")
    }
    else
    {
        Write-Host "`n$Message`n"
        Write-Host "Press a key to continue" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}
## /*************************************************************************************/
14
## Take ownership of files and folders.
## void TakeOwn(string Path);
## /*************************************************************************************/

function TakeOwn {
	param(
		[string]$Path
	)
	$Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList "$env:USERDOMAIN\$env:USERNAME"
	$Acl = $null
	if(Test-Path $Path -PathType Container)
	{
		$ItemList = Get-ChildItem $Path -Recurse
		foreach ($Item in $ItemList) {
			$Acl = Get-Acl -Path $Item.FullName # Get the ACL from the item
			$Acl.SetOwner($Account) # Update the in-memory ACL
			Set-Acl -Path $Item.FullName -AclObject $Acl  # Set the updated ACL on the target item
			$Item.Attributes = $Item.Attributes -band -bnot ([System.IO.FileAttributes]::ReadOnly).value__;
			$Item.Attributes = $Item.Attributes -band -bnot ([System.IO.FileAttributes]::System).value__;
			$Item.Attributes = $Item.Attributes -band -bnot ([System.IO.FileAttributes]::Hidden).value__;
		}
	}
	else
	{
		$Acl = Get-Acl $Path # Get the ACL from the item
		$Acl.SetOwner($Account) # Update the in-memory ACL
		Set-Acl -Path $Item.FullName -AclObject $Acl  # Set the updated ACL on the target item
		$Path.Attributes = $Path.Attributes -band -bnot ([System.IO.FileAttributes]::ReadOnly).value__;
		$Path.Attributes = $Path.Attributes -band -bnot ([System.IO.FileAttributes]::System).value__;
		$Path.Attributes = $Path.Attributes -band -bnot ([System.IO.FileAttributes]::Hidden).value__;
	}
}

## /*************************************************************************************/

## Open system protection.
## void sysProtection();
## /*************************************************************************************/
function SysProtection {
	PrintTop -Title "Opening the system protection."

	if ($Family -ne 5) {
		start systempropertiesprotection
	} else {
		$Pause.Invoke("Sorry, this option is not available on this Operating System.")
	}
}

## /*************************************************************************************/


## Run the reset Windows Update components.
## void components();
## /*************************************************************************************/
function Components {
	## ----- Stopping the Windows Update services -----
	PrintTop -Title "Stopping the Windows Update services."
	net stop bits

	PrintTop -Title "Stopping the Windows Update services."
	net stop wuauserv

	PrintTop -Title "Stopping the Windows Update services."
	net stop appidsvc

	PrintTop -Title "Stopping the Windows Update services."
	net stop cryptsvc

	PrintTop -Title "Closing the Windows Update process."
	taskkill /im wuauclt.exe /f

	## ----- Checking the services status -----
	PrintTop -Title "Checking the services status."

    $ServiceInfo = Get-Service -Name "bits"
	if(!$ServiceInfo.Status -match "Stopped") {
         Pause -Message "Failed to stop the Background Intelligent Transfer service."
    }

	PrintTop -Title "Checking the services status."

    $ServiceInfo = Get-Service -Name "wuauserv"
	if(!$ServiceInfo.Status -match "Stopped") {
        Pause -Message "Failed to stop the Windows Update service."
    }

	PrintTop -Title "Checking the services status."

    $ServiceInfo = Get-Service -Name "appidsvc"
	if(!$ServiceInfo.Status -match "Stopped") {
        Pause -Message "Failed to stop the Application Identity service."
    }

	PrintTop -Title "Checking the services status."

    $ServiceInfo = Get-Service -Name "cryptsvc"
	if(!$ServiceInfo.Status -match "Stopped") {
        Pause -Message "Failed to stop Cryptographic Services."
    }

	## ----- Delete the qmgr*.dat files -----
	PrintTop -Title "Deleting the qmgr*.dat files."

	Remove-Item -Recurse -Force "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
	Remove-Item -Recurse -Force "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.dat"

	## ----- Renaming the softare distribution folders backup copies -----
	PrintTop -Title "Deleting the old software distribution backup copies."

	Set-Location $env:SystemRoot

	if(Test-Path "$env:SystemRoot\winsxs\pending.xml.bak") {
	    Remove-Item -Recurse -Force "$env:SystemRoot\winsxs\pending.xml.bak"
	}
	if(Test-Path "$env:SystemRoot\SoftwareDistribution.bak") {
		Remove-Item -Recurse -Force "$env:SystemRoot\SoftwareDistribution.bak"
	}
	if(Test-Path "env:SystemRoot\system32\Catroot2.bak") {
	    Remove-Item -Recurse -Force "env:SystemRoot\system32\Catroot2.bak"
	}
	if(Test-Path "$env:SystemRoot\WindowsUpdate.log.bak") {
		Remove-Item -Recurse -Force "env:SystemRoot\WindowsUpdate.log.bak"
	}

    PrintTop -Title "Renaming the software distribution folders."

	if(Test-Path "$env:SystemRoot\winsxs\pending.xml") {
        TakeOwn -Path "$env:SystemRoot\winsxs\pending.xml"
		Move-Item "%SYSTEMROOT%\winsxs\pending.xml" pending.xml.bak
	}
	if(Test-Path "$env:SystemRoot\SoftwareDistribution") {
        TakeOwn -Path "$env:SystemRoot\SoftwareDistribution";
		Move-Item "$env:SystemRoot\SoftwareDistribution" SoftwareDistribution.bak
		if(Test-Path "$env:SystemRoot\SoftwareDistribution") {
            Pause -Message "Failed to move SoftwareDistribution folder."
		}
	}
	if(Test-Path "$env:SystemRoot\system32\Catroot2") {
		TakeOwn -Path "$env:SystemRoot\system32\Catroot2"
		Move-Item "$env:SystemRoot\system32\Catroot2" Catroot2.bak
	}
	if(Test-Path "$env:SystemRoot\WindowsUpdate.log") {
		TakeOwn -Path "$env:SystemRoot\WindowsUpdate.log"
		Move-Item "$env:SystemRoot\WindowsUpdate.log" WindowsUpdate.log.bak
	}

	## ----- Reset the BITS service and the Windows Update service to the default security descriptor -----
	PrintTop -Title "Reset the BITS service and the Windows Update service to the default security descriptor."
	CMD /C "sc.exe sdset wuauserv D:(A;CI;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)"
	CMD /C "sc.exe sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;SAFA;WDWO;;;BA)"
	CMD /C "sc.exe sdset cryptsvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SO)(A;;CCLCSWLORC;;;AC)(A;;CCLCSWLORC;;;S-1-15-3-1024-3203351429-2120443784-2872670797-1918958302-2829055647-4275794519-765664414-2751773334)"
	CMD /C "sc.exe sdset trustedinstaller D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;SAFA;WDWO;;;BA)"

	## ----- Reregister the BITS files and the Windows Update files -----
	PrintTop -Title "Reregister the BITS files and the Windows Update files."

	Set-Location "$env:SystemRoot\system32"
	regsvr32.exe /s atl.dll
	regsvr32.exe /s urlmon.dll
	regsvr32.exe /s mshtml.dll
	regsvr32.exe /s shdocvw.dll
	regsvr32.exe /s browseui.dll
	regsvr32.exe /s jscript.dll
	regsvr32.exe /s vbscript.dll
	regsvr32.exe /s scrrun.dll
	regsvr32.exe /s msxml.dll
	regsvr32.exe /s msxml3.dll
	regsvr32.exe /s msxml6.dll
	regsvr32.exe /s actxprxy.dll
	regsvr32.exe /s softpub.dll
	regsvr32.exe /s wintrust.dll
	regsvr32.exe /s dssenh.dll
	regsvr32.exe /s rsaenh.dll
	regsvr32.exe /s gpkcsp.dll
	regsvr32.exe /s sccbase.dll
	regsvr32.exe /s slbcsp.dll
	regsvr32.exe /s cryptdlg.dll
	regsvr32.exe /s oleaut32.dll
	regsvr32.exe /s ole32.dll
	regsvr32.exe /s shell32.dll
	regsvr32.exe /s initpki.dll
	regsvr32.exe /s wuapi.dll
	regsvr32.exe /s wuaueng.dll
	regsvr32.exe /s wuaueng1.dll
	regsvr32.exe /s wucltui.dll
	regsvr32.exe /s wups.dll
	regsvr32.exe /s wups2.dll
	regsvr32.exe /s wuweb.dll
	regsvr32.exe /s qmgr.dll
	regsvr32.exe /s qmgrprxy.dll
	regsvr32.exe /s wucltux.dll
	regsvr32.exe /s muweb.dll
	regsvr32.exe /s wuwebv.dll

	## ----- Resetting Winsock -----
	PrintTop -Title "Resetting Winsock."
	netsh winsock reset

	## ----- Resetting WinHTTP Proxy -----
	PrintTop -Title "Resetting WinHTTP Proxy."

	if( $Family -eq 5 ) {
		proxycfg.exe -d
	} else {
		netsh winhttp reset proxy
	}

	## ----- Set the startup type as automatic -----
	PrintTop -Title "Resetting the services as automatics."
	CMD /C "sc.exe config wuauserv start= auto"
	CMD /C "sc.exe config bits start= delayed-auto"
	CMD /C "sc.exe config cryptsvc start= auto"
	CMD /C "sc.exe config TrustedInstaller start= demand"
	CMD /C "sc.exe config DcomLaunch start= auto"

	## ----- Starting the Windows Update services -----
	PrintTop -Title "Starting the Windows Update services."
	net start bits

	PrintTop -Title "Starting the Windows Update services."
	net start wuauserv

	PrintTop -Title "Starting the Windows Update services."
	net start appidsvc

	PrintTop -Title "Starting the Windows Update services."
	net start cryptsvc

	PrintTop -Title "Starting the Windows Update services."
	net start DcomLaunch

	## ----- End process -----
    Pause -Message "The operation completed successfully."
}
## /*************************************************************************************/


## Delete temporary files in Windows.
## void temp();
## /*************************************************************************************/
function temp {
	PrintTop -Title "Deleting the temporary files in Windows."

	Remove-Item -Recurse -Force "$env:TEMP\*.*"
	Remove-Item -Recurse -Force "$env:SystemRoot\Temp\*.*"

    Pause -Message "Process complete"

}
## /*************************************************************************************/


## Open the Internet Explorer options.
## void iOptions();
## /*************************************************************************************/
function iOptions {
	PrintTop -Title "Opening the Internet Explorer options."

	start InetCpl.cpl
}
## /*************************************************************************************/


## Check and repair errors on the disk.
## void chkdsk();
## /*************************************************************************************/
Function chkdsk {
	PrintTop -Title "Check the file system and file system metadata of a volume for logical and physical errors (CHKDSK.exe)."

	CMD /C "chkdsk %HOMEDRIVE% /f /r"

	if ($LASTEXITCODE -eq 0) {
		Pause -Message "The operation completed successfully."
	} else {
        Pause -Message "An error occurred during operation."
	}
}
## /*************************************************************************************/


## Scans all protected system files.
## void sfc();
## /*************************************************************************************/
function sfc {
	PrintTop -Title "Scan your system files and to repair missing or corrupted system files (SFC.exe)."

	if( $Family -ne 5 ) {
		sfc /scannow
	} else {
		Pause -Message "Sorry, this option is not available on this Operating System."
        Return
	}

	if ($LASTEXITCODE -eq 0) {
        Pause -Message "The operation completed successfully."
	} else {
		Pause -Message "An error occurred during operation."
	}

}
## /*************************************************************************************/


## Scan the image to check for corruption.
## void dism1();
## /*************************************************************************************/
function dism1 {
	PrintTop -Title "Scan the image for component store corruption (The DISM /ScanHealth argument)."

	if (($Family -eq 8) -or ($Family -eq 10) -or ($Family -eq 11)) {
		CMD /C "Dism.exe /Online /Cleanup-Image /ScanHealth"
	} else {
		pause -message "Sorry, this option is not available on this Operating System."
        return
	}

	if ($LASTEXITCODE -eq 0) {
        Pause -Message "The operation completed successfully."
	} else {
		Pause -Message "An error occurred during operation."
	}
}
## /*************************************************************************************/


## Check the detected corruptions.
## void dism2();
## /*************************************************************************************/
function dism2 {
	PrintTop -Title "Check whether the image has been flagged as corrupted by a failed process and whether the corruption can be repaired (The DISM /CheckHealth argument)."

	if (($Family -eq 8) -or ($Family -eq 10) -or ($Family -eq 11)) {
		CMD /C "Dism.exe /Online /Cleanup-Image /CheckHealth"
	} else {
		pause -message "Sorry, this option is not available on this Operating System."
        return
	}

	if ($LASTEXITCODE -eq 0) {
        Pause -Message "The operation completed successfully."
	} else {
		Pause -Message "An error occurred during operation."
	}
}
## /*************************************************************************************/


## Repair the Windows image.
## void dism3();
## /*************************************************************************************/
function dism3 {
	PrintTop -Title "Scan the image for component store corruption, and then perform repair operations automatically (The DISM /RestoreHealth argument)."

	if (($Family -eq 8) -or ($Family -eq 10) -or ($Family -eq 11)) {
		CMD /C "Dism.exe /Online /Cleanup-Image /RestoreHealth"
	} else {
		pause -message "Sorry, this option is not available on this Operating System."
        return
	}

	if ($LASTEXITCODE -eq 0) {
        Pause -Message "The operation completed successfully."
	} else {
		Pause -Message "An error occurred during operation."
	}
}
## /*************************************************************************************/


## Clean up the superseded components.
## void dism4();
## /*************************************************************************************/
function dism4 {
	PrintTop -Title "Clean up the superseded components and reduce the size of the component store (The DISM /StartComponentCleanup argument)."

	if (($Family -eq 8) -or ($Family -eq 10) -or ($Family -eq 11)) {
		CMD /C "Dism.exe /Online /Cleanup-Image /StartComponentCleanup"
	} else {
		pause -message "Sorry, this option is not available on this Operating System."
        return
	}

	if ($LASTEXITCODE -eq 0) {
        Pause -Message "The operation completed successfully."
	} else {
		Pause -Message "An error occurred during operation."
	}
}
## /*************************************************************************************/


## Reset registry values.
## void regedit();
## /*************************************************************************************/
function regedit {
    #$dateAndTime = Get-Date -Format "yyyy-MM-dd HH:mm"
    $currentDate = Get-Date -Format "yyyy-MM-dd"
    $choices = '&Yes', '&No'
    
    if(-not (Test-Path "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\" -PathType Container)) {
        mkdir "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\"
    }

	## ----- Create a backup of the Registry -----
	PrintTop -Title "Making a backup of the Registry in: $env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\"

	if (Test-Path "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKLM.reg" -PathType Leaf) {
		Write-Output "It appears there is a current backup of the registry."
        $decision = $Host.UI.PromptForChoice('Backup found!', 'Are you sure you want to proceed?', $choices, 1)
        if($decision -ne 0)
        {
            Pause -Message "Please manually remove or update backup before continuing."
    		return
        }
	} else {
		reg Export HKCR "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKCR.reg"
		reg Export HKCU "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKCU.reg"
		reg Export HKLM "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKLM.reg"
		reg Export HKU "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKU.reg"
		reg Export HKCC "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKCC.reg"
	## ----- Checking backup -----
    	PrintTop -Title "Checking the backup."
        if( -not(Test-Path "$env:USERPROFILE\Desktop\Backup\Regedit\$currentDate\HKLM.reg")) {
		    Write-Output "An unexpected error has occurred."
		    Write-Output "`nUnable to verify backup has been created."
		    Pause -Message "Please manually create a backup of the registry before continuing."
            return
	    } else {
            Write-Output "Backup successfully created!"
	    }
	}

	## ----- Delete keys in the Registry -----
	PrintTop -Title "Deleting values in the Registry."

	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
	reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /f
	reg delete "HKCU\Software\Microsoft\WindowsSelfHost" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
	reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /f
	reg delete "HKLM\Software\Microsoft\WindowsSelfHost" /f
	reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f

	reg delete "HKLM\COMPONENTS\PendingXmlIdentifier" /f
	reg delete "HKLM\COMPONENTS\NextQueueEntryIndex" /f
	reg delete "HKLM\COMPONENTS\AdvancedInstallersNeedResolving" /f
	reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v ResetClient /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v ResetDataStoreReason /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientIDValidation /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUState /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v LastWaitTimeout /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v DetectionstartTime /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NextDetectionTime /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results" /f

	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Reporting" /v SamplingValue /f
	reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services" /v ReregisterAuthorizationCab /f

	## ----- Add keys in the Registry -----
	PrintTop -Title "Adding values in the Registry."

	$key="HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX"
	AddRegistryValue -Key $key -Value "IsConvergedUpdateStackEnabled" -Type "REG_DWORD" -Data "0"

	$key="HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    AddRegistryValue -Key $key -Value "UxOption" -Type "REG_DWORD" -Data "0"

    $key="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
	AddRegistryValue -Key $key -Value "AppData" -Type "REG_EXPAND_SZ" -Data "%USERPROFILE%\AppData\Roaming"

	$key="HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
	AddRegistryValue -Key $key -Value "AppData" -Type "REG_EXPAND_SZ" -Data "%USERPROFILE%\AppData\Roaming"

	$key="HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
	AddRegistryValue -key $key -Value "AppData" -Type "REG_EXPAND_SZ" -Data "%USERPROFILE%\AppData\Roaming"

	reg add "HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup" /f

	reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v Security_HKLM_only | find /i "Security_HKLM_Only" | find "1"

	if ($LASTEXITCODE -eq 0) {
		$key="HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
	} else {
		$key="HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
	}

	AddRegistryValue -Key "$key\microsoft.com\update" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\microsoft.com\update" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\microsoft.com\windowsupdate" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\update.microsoft.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\update.microsoft.com" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.microsoft.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\download.microsoft.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.com" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.com\download" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windowsupdate.com\download" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\download.windowsupdate.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\download.windowsupdate.com" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\windows.com\wustat" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\wustat.windows.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\microsoft.com\ntservicepack" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\ntservicepack.microsoft.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\microsoft.com\ws" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\microsoft.com\ws" -Value "https" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\ws.microsoft.com" -Value "http" -Type "REG_DWORD" -Data "2"
	AddRegistryValue -Key "$key\ws.microsoft.com" -Value "https" -Type "REG_DWORD" -Data "2"

	## ----- End process -----
    Pause -Message "The operation completed successfully."
}
## /*************************************************************************************/


## Reset Winsock setting.
## void winsock();
## /*************************************************************************************/
function winsock {
	## ----- Reset Winsock control -----
	PrintTop -Title "Reset Winsock control."

	PrintTop -Title "Restoring transaction logs."
	CMD /C "fsutil resource setautoreset true C:\"

	PrintTop -Title "Restoring TPC/IP."
	CMD /C "netsh int ip reset"

	PrintTop -Title "Restoring Winsock."
	CMD /C "netsh winsock reset"

	PrintTop -Title "Restoring default policy settings."
	CMD /C "netsh advfirewall reset"

	PrintTop -Title "Restoring the DNS cache."
	CMD /C "ipconfig /flushdns"

	PrintTop -Title "Restoring the Proxy."
	CMD /C "netsh winhttp reset proxy"

	## ----- End process -----
	Pause -Message "The operation completed successfully."
}
## /*************************************************************************************/


## Forcing group policy update.
## void gpupdate();
## /*************************************************************************************/
function gpupdate {
	PrintTop -Title "Forcing group policy update."

    #Pause -Message "Sorry, this option is currently unavailable."
	if ($Family -eq 5) {
		Pause -Message "Sorry, this option is not available on this Operating System."
        return
	} else {
		CMD /C "gpupdate /force"
	    if ($LASTEXITCODE -eq 0) {
		    Pause -Message "The operation completed successfully."
	    } else {
            Pause -Message "An error occurred during operation."
	    }
	}


}
## /*************************************************************************************/


## Search Updates.
## void updates();
## /*************************************************************************************/
function updates {
	PrintTop -Title "Looking for updates."
    Write-Output "This may take some time"

	CMD /C "wuauclt /resetauthorization /detectnow"

	if(($Family -eq 10) -or ($Family -eq 11)) {
		start ms-settings:windowsupdate-action
	} elseif ($Family -ne 5) {
		start wuapp.exe
	} else {
		Pause -Message "Sorry, this option is not available on this Operating System."
	}
}
## /*************************************************************************************/


## Reset the Windows Store.
## void wsreset();
## /*************************************************************************************/
function wsreset {
	PrintTop -Title "Resetting the Windows Store."
    if(($Family -eq 8) -or ($Family -eq 10) -or ($Family -eq 11))
    {
	    wsreset
    } else {
		Pause -Message "Sorry, this option is not available on this Operating System."
        return
    }
}
## /*************************************************************************************/


## Get the Windows Product Key.
## void productKey();
## /*************************************************************************************/
function productKey {
	PrintTop -Title "Getting the Windows Product Key."
    
	$productKey = wmic path SoftwareLicensingService get OA3xOriginalProductKey
    Write-Output $productKey

    Pause -Message "Product Key Found"
}
## /*************************************************************************************/


## Explore other local solutions.
## void local();
## /*************************************************************************************/
function local {
	PrintTop -Title "Looking for solutions in this PC."

	if ($Family -ne 5) {
		start control.exe /name Microsoft.Troubleshooting
	} else {
		Pause -Message "Sorry, this option is not available on this Operating System."
        return
	}
}
## /*************************************************************************************/


## Explore other online solutions.
## void online();
## /*************************************************************************************/
function online {
	PrintTop -Title "Looking for solutions Online."

	start 'https://support.microsoft.com/en-us/gp/windows-update-issues/'
}
## /*************************************************************************************/


## Reboot the system.
## void restart();
## /*************************************************************************************/
function restart {
	PrintTop -Title "Restart your PC."

	if($Family -ne 5) {
		Write-Output "The system will reboot in 60 seconds."
		Write-Output "Please save all open documents."

		CMD /C "shutdown.exe /r /t 60 /c `"The system will reboot in 60 seconds. Please save all open documents.`""
	} else {
		Pause -Message "Sorry, this option is not available on this Operating System."
        return
	}
    Close
}
## /*************************************************************************************/


## Open help file.
## void help();
## /*************************************************************************************/
function help {
	start 'https://github.com/ManuelGil/Reset-Windows-Update-Tool/wiki'
}
## /*************************************************************************************/


## diagnostic tools menu.
## void diagnostic();
## /*************************************************************************************/
function diagnostic {
    do {
	    PrintTop -Title "Download and run diagnostics for your system."

	    Write-Out "    1. Windows Update on Windows 8 and Windows 8.1.
	        2. Windows Update on Windows 10.
	        3. Apps on Windows 8.1.
	        4. Apps on Windows 10.
	
	                                                            0. Back."

	    $userOption = Read-Host("Select an option")
        switch ($userOption) {
	        0 {
                return
            }
	        1 {
		        start 'http://go.microsoft.com/?linkid=9830262'
            }
            2 {
    		    start 'http://aka.ms/diag_wu'
            }
            3 {
	    	    start 'http://go.microsoft.com/fwlink/p/?LinkId=268423'
            }
	        4 {
		        start 'http://aka.ms/diag_apps10'
            }
            default {
                Write-Host "`nInvalid Option`n"
                $Pause.Invoke("Press any key to continue...")
            }
        }
    } while ($userOption -ne 0)
}
## /*************************************************************************************/


## End tool.
## void close();
## /*************************************************************************************/
function Close {
	exit
}
## /*************************************************************************************/

initialize