[string]$BaseUrl = "https://192.168.50.60/auth"
[string]$Username = "admin"

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
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -SkipCertificateCheck
        return $response.access_token
    }
    catch {
        Write-Host "Failed to get access token: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

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
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -SkipCertificateCheck
        foreach ($component in $response) {
            if ($component.providerId -eq "ldap" -and $component.parentId -eq "Zerto") {
                Write-Host "Found LDAP provider." -ForegroundColor Green
                Write-Host $component
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
        $response = Invoke-WebRequest -Uri $url -Method Put -Headers $headers -Body $body -SkipCertificateCheck -UseBasicParsing
        if ($response.StatusCode -eq 204) {
            Write-Host "New password accepted." -ForegroundColor Green
        } else {
            Write-Host "Failed to update password, received status code: $($response.StatusCode)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to update password: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main script

# Ask for Keycloak admin password
$AdminPassword = Read-Host -AsSecureString -Prompt "Enter Keycloak admin password"
$AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))

# Get access token
$AccessToken = Get-AccessToken -BaseUrl $BaseUrl -Username $Username -AdminPassword $AdminPassword
Write-Host "Connected to Keycloak." -ForegroundColor Green

# Get LDAP component
$LdapComponent = Get-LdapComponent -BaseUrl $BaseUrl -AccessToken $AccessToken

# Ask for the new LDAP bind password
$NewPassword = Read-Host -AsSecureString -Prompt "Enter new LDAP bind password"
$NewPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))

# Update LDAP bind password
Update-LdapPassword -BaseUrl $BaseUrl -Component $LdapComponent -AccessToken $AccessToken -NewPassword $NewPassword
