 # This script should be ran to automatically create a scheduled task which runs the rotate-bind-pw.ps1 script
 
 # Define the script path
 $scriptPath = "C:\scripts\rotate-pass.ps1"

 # Create the action to run the PowerShell script
 $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`" -ExecutionPolicy Bypass"
 
 # Create the trigger to run every 30 days
 $trigger = New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Days 30)
 
 # Create the principal to run as the current user
 $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
 
 # Register the task
 Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "UpdateZertoKeycloakPassword" -Description "Task to update AD and Zerto Keycloak LDAP password every 30 days"
  
 