#Event-Parsing: Thanks to http://blogs.technet.com/b/ashleymcglone/archive/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs.aspx
#Get-Acl: Thanks to http://blogs.technet.com/b/heyscriptingguy/archive/2009/09/14/hey-scripting-guy-september-14-2009.aspx
$Events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";id=1;}

#Well-known SIDs https://support.microsoft.com/en-us/kb/243330
###LocalSIDs###
#S-1-1-0 Everyone
#S-1-5-7 Anonymous
#S-1-5-11 Authenticated Users
#S-1-5-13 Terminal Server Users
#S-1-5-14 Remote Interactive Logon
#S-1-5-32-545 Users
#S-1-5-32-546 Guests
#S-1-5-32-547 PowerUsers
#S-1-5-32-555 Remote Desktop Users
###DomainSIDs###
#S-1-5-21domain-501 Domain Guest
#S-1-5-21domain-513 Domain Users

#Define "vulnerable" SIDs
$LocalSIDs_regex  = "(S-1-1-0|S-1-5-7|S-1-5-11|S-1-5-13|S-1-5-14|S-1-5-32-545|S-1-5-32-546|S-1-5-32-547|S-1-5-32-555)"
$DomainSIDs_regex = "(S-1-5-21[0-9-]+-501|S-1-5-21[0-9-]+-513)"
#Enumerate local administrator accounts
$LocalAdministrators = @()
get-wmiobject -Class "Win32_Group" -filter "LocalAccount = $TRUE And SID = 'S-1-5-32-544'"  | foreach-object {
      $groupName = $_.Name
      $_.GetRelated("Win32_Account","Win32_GroupUser","","",
        "PartComponent","GroupComponent",$FALSE,$WMIEnumOpts) | foreach-object {
			$LocalAdministrators = $LocalAdministrators  +  $_.Caption
		}
    }

ForEach ($Event in $Events) {            
    #Convert the events to XML            
    $eventXML = [xml]$Event.ToXml()            
    
	#Iterate through each one of the XML message properties            
    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
        
		#Extract process image path           
        If (($eventXML.Event.EventData.Data[$i].name -eq "Image")){
			$Image = $eventXML.Event.EventData.Data[$i].'#text'
		}		
		#Identify processes that are executed in context of NT-AUTHORITY\SYSTEM
		If ($eventXML.Event.EventData.Data[$i].name -eq "User") {
			$match = $FALSE;
			If ($eventXML.Event.EventData.Data[$i].'#text' -match "NT-AUTH?ORIT(Y|ÄT)\\SYSTEM"){
				$match = $TRUE;
			}
			Else {
				Foreach ($Administrator in $LocalAdministrators ){
					If ($eventXML.Event.EventData.Data[$i].'#text' -eq $Administrator){
							$match = $TRUE
					}
				}
			}
			
			If ($match){
				#Get Access Control List from process image
				if($imageACLs = Get-Acl $Image -ErrorAction SilentlyContinue){
				
					ForEach($ACL in $imageACLs.Access){
						
						If ($ACL.FileSystemRights -match "(FullControl|Modify|Write)"){
							If($ACL.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -match $LocalSIDs_regex){
								Write-Host "====================================================="
								Write-Host "Vulnerable program:" 
								Write-Host $Image
								Write-Host "  Authorized group: " $ACL.IdentityReference.Value
								Write-Host "=====================================================`n`n"
							}
							If($ACL.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -match $DomainSIDs_regex){
								Write-Host "====================================================="
								Write-Host "Vulnerable program:" 
								Write-Host $Image
								Write-Host "  Authorized group: " $ACL.IdentityReference.Value
								Write-Host "=====================================================`n`n"
							}
						}
						
					}
				}
				Else {
					Write-Host "Could not retrieve ACL from " $Image "`n`n"
				}
			}
		}
		
    } 
           
}      

#$Events