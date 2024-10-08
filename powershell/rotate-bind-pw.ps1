 # This script, if ran by a user with active directory admin rights, will do the following:
 # - Generate a new password
 # - Set the new password in AD
 # - Connect to Keycloak and set the password in keycloak for the ldap bind user

 # Change the parameters below to your environment
 
 # Parameters
 [string]$BaseUrl = "https://192.168.50.60/auth"        # Keycloak base URL
 [string]$Username = "admin"                            # Keycloak admin username
 [string]$AdminPassword = "keycloakadminpassword"       # Keycloak admin password
 [string]$BindUserName = "zertosvcusername"             # AD Bind User name
 [int]$PasswordLength = 20                              # Desired length for the random password
 
 
 # Disable SSL certificate validation
 Add-Type @"
     using System.Net;
     using System.Security.Cryptography.X509Certificates;
 
     public class TrustAllCertsPolicy : ICertificatePolicy {
         public bool CheckValidationResult(
             ServicePoint srvPoint, X509Certificate certificate,
             WebRequest request, int certificateProblem) {
             return true;
         }
     }
 "@
 
 [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
 
 
 
 # Function to generate a random password
 function Generate-RandomPassword {
     param (
         [int]$length = 20
     )
     
     # Define the character sets as arrays of strings
     $lowercase = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
     $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
     $numbers = '0123456789'.ToCharArray()
     $special = '!@#$%^&*()-_=+[]{}<>?'.ToCharArray()
     
     # Ensure that the password includes at least two lowercase, two uppercase, two numbers, and two special characters
     $selectedLowercase = -join (Get-Random -InputObject $lowercase -Count 2)
     $selectedUppercase = -join (Get-Random -InputObject $uppercase -Count 2)
     $selectedNumbers = -join (Get-Random -InputObject $numbers -Count 2)
     $selectedSpecial = -join (Get-Random -InputObject $special -Count 2)
     
     # Remaining characters to meet length requirement
     $remainingLength = $length - 8  # We've already chosen 8 characters
     $allCharacters = $lowercase + $uppercase + $numbers + $special
     $remaining = -join (Get-Random -InputObject $allCharacters -Count $remainingLength)
     
     # Combine all parts and shuffle the result to ensure randomness
     $passwordArray = ($selectedLowercase + $selectedUppercase + $selectedNumbers + $selectedSpecial + $remaining).ToCharArray() | Sort-Object {Get-Random}
     $password = -join $passwordArray
     return $password
 }
 
 # Function to update the password in Active Directory
 function Update-ADPassword {
     param (
         [string]$BindUserName,
         [string]$NewPassword
     )
     
     try {
         # Update the password in Active Directory
         Set-ADAccountPassword -Identity $BindUserName -Reset -NewPassword (ConvertTo-SecureString -String $NewPassword -AsPlainText -Force)
         Write-Host "Active Directory password updated successfully." -ForegroundColor Green
     }
     catch {
         Write-Host "Failed to update password in Active Directory: $($_.Exception.Message)" -ForegroundColor Red
         exit 1
     }
 }
 
 # Function to get access token
 function Get-AccessToken {
     param (
         [string]$BaseUrl,
         [string]$Username,
         [string]$AdminPassword
     )
     
     $url = "$BaseUrl/realms/zerto/protocol/openid-connect/token"
     $body = @{
         client_id   = "admin-cli"
         username    = $Username
         password    = $AdminPassword
         grant_type  = "password"
     }
     
     try {
         $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
         return $response.access_token
     }
     catch {
         Write-Host "Failed to get access token: $($_.Exception.Message)" -ForegroundColor Red
         exit 1
     }
 }
 
 # Function to get the LDAP component in Keycloak
 function Get-LdapComponent {
     param (
         [string]$BaseUrl,
         [string]$AccessToken
     )
     
     $url = "$BaseUrl/admin/realms/zerto/components?type=org.keycloak.storage.UserStorageProvider"
     $headers = @{
         Authorization = "Bearer $AccessToken"
     }
 
     try {
         $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
         foreach ($component in $response) {
             if ($component.providerId -eq "ldap" -and $component.parentId -eq "Zerto") {
                 Write-Host "Found LDAP provider." -ForegroundColor Green
                 return $component
             }
         }
         Write-Host "LDAP provider not found." -ForegroundColor Red
         exit 1
     }
     catch {
         Write-Host "Failed to get LDAP component: $($_.Exception.Message)" -ForegroundColor Red
         exit 1
     }
 }
 
 # Function to update LDAP password in Keycloak
 function Update-LdapPassword {
     param (
         [string]$BaseUrl,
         [object]$Component,
         [string]$AccessToken,
         [string]$NewPassword
     )
     
     $url = "$BaseUrl/admin/realms/zerto/components/$($Component.id)"
     $Component.config.bindCredential = @($NewPassword)  # Update password in config
     
     $headers = @{
         Authorization = "Bearer $AccessToken"
         "Content-Type" = "application/json"
     }
 
     $body = $Component | ConvertTo-Json -Depth 10
 
     try {
         $response = Invoke-WebRequest -Uri $url -Method Put -Headers $headers -Body $body -UseBasicParsing
         if ($response.StatusCode -eq 204) {
             Write-Host "New password accepted in Keycloak." -ForegroundColor Green
         } else {
             Write-Host "Failed to update password in Keycloak, received status code: $($response.StatusCode)" -ForegroundColor Red
         }
     }
     catch {
         Write-Host "Failed to update password in Keycloak: $($_.Exception.Message)" -ForegroundColor Red
     }
 }
 
 # Main script execution
 
 # Generate a new random password
 $NewPassword = Generate-RandomPassword -length $PasswordLength
 Write-Host "Generated new random password."
 
 # Update the password in Active Directory
 Update-ADPassword -BindUserName $BindUserName -NewPassword $NewPassword
 
 # Get access token from Keycloak
 $AccessToken = Get-AccessToken -BaseUrl $BaseUrl -Username $Username -AdminPassword $AdminPassword
 Write-Host "Connected to Keycloak." -ForegroundColor Green
 
 # Get LDAP component in Keycloak
 $LdapComponent = Get-LdapComponent -BaseUrl $BaseUrl -AccessToken $AccessToken
 
 # Update LDAP password in Keycloak
 Update-LdapPassword -BaseUrl $BaseUrl -Component $LdapComponent -AccessToken $AccessToken -NewPassword $NewPassword
  
 