# ====================================================================
#  Azure KeyVault Certificate Orchestrator v0.3
#  Robert Furniss
#  Distributed under the MIT License
#  https://github.com/RobFDev/azure-keyvault-certificate-orchestrator
# ====================================================================

# - Better DRY code and general tidy up.
# - Better checks and error handling in general
# - Properly standardise variable names
# - In the "Get Available Certificate" returned array, the Keyvault name parameter is not mandatory
# - $Path should be defined as global variable as it is used in multiple locations and should not change throughout
# - Wrap function for building out certificate directories with checks.
# - The Below exception does not get caught when listing certificates. Authentication and errors doing so should be parsed on script init:
#     Get-AzKeyVaultCertificate : Your Azure credentials have not been set up or have expired, please run Connect-AzAccount
#     to set up your Azure credentials.
#     You must use multi-factor authentication to access resource AzureKeyVaultServiceEndpointResourceId, please rerun
#     'Connect-AzAccount' with additional parameter '-AuthScope AzureKeyVaultServiceEndpointResourceId'.
#     At D:\Repos\certops_dev\certmanage.ps1:119 char:14
#     +     $certs = Get-AzKeyVaultCertificate -VaultName $KeyVault
#     +              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#         + CategoryInfo          : CloseError: (:) [Get-AzKeyVaultCertificate], AzPSArgumentException
#         + FullyQualifiedErrorId : Microsoft.Azure.Commands.KeyVault.GetAzureKeyVaultCertificate

$subscriptionName = "x"
$keyVaultName  = "x"
$CertificateAttributes = "C=x,ST=x,L=x,O=x,OU=x"

function Invoke-ModuleCheck
{
    if(!(Get-Module -ListAvailable -Name Az.KeyVault))
    {
        try 
        {
            Import-Module Az.KeyVault
        }
        catch
        {
            Write-Host "Failed to import Az.KeyVault module"
            Write-Host "Install it from https://github.com/Azure/azure-powershell/releases"
            exit
        }
    }

    if(!(Get-Module -ListAvailable -Name Az.Accounts))
    {
        try 
        {
            Import-Module Az.Accounts
        }
        catch
        {
            Write-Host "Failed to import Az.Accounts module"
            Write-Host "Install it from https://github.com/Azure/azure-powershell/releases"
            exit
        }
    }
}

function Set-AzureSubscription
{
    param
    (
        [parameter(Mandatory=$true)]
        [string]$SubscriptionName
    )
    
    try
    {
        Set-AzContext -Subscription $SubscriptionName
    }
    catch
    {
        Write-Host "Failed to set Azure subscription - are you logged into az?"
        Write-Host "Do an 'az login' and try again"
        exit
    }
}

function Show-OptionPicker 
{
    param 
    (
        [string[]]$Options
    )

    $validOptionNumbers = 1..$Options.Count
    $selectedOption = $null

    while ($null -eq $selectedOption)
    {
        Clear-Host
        Write-Host "Select an option:"
        for ($i = 0; $i -lt $Options.Count; $i++)
        {
            Write-Host "[$($i + 1)] $($Options[$i])"
        }

        $userInput = Read-Host "Enter the number of your choice (1-$($Options.Count))"

        if ($userInput -match '^\d+$' -and $validOptionNumbers -contains $userInput)
        {
            $selectedOption = $Options[$userInput - 1]
        }
        else
        {
            Write-Host "Invalid input. Please enter a number between 1 and $($Options.Count)."
            Start-Sleep -Seconds 2
        }
    }

    return $selectedOption
}

function Get-RandomPassword
{
    param 
    (
        [int]$PasswordLength = 16
    )

    $CharacterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $Password = ""

    for ($i = 0; $i -lt $PasswordLength; $i++)
    {
        $RandomIndex = Get-Random -Minimum 0 -Maximum $CharacterSet.Length
        $Password += $CharacterSet[$RandomIndex]
    }

    return $Password
}

function Search-DNSMatch {
    param (
        [string]$userInput,
        [string[]]$dnsNames
    )

    $matchingResults = @()

    $userInput = $userInput -replace '\.', '-'

    foreach ($dnsName in $dnsNames) {
        $dnsNameLower = $dnsName.ToLower()

        if ($dnsNameLower -eq $userInput.ToLower()) {
            $matchingResults += $dnsName
        } elseif ($dnsNameLower -like "*$userInput*") {
            $matchingResults += $dnsName
        }
    }

    return $matchingResults
}

function Get-AvailableCertArray
{
    param
    (
        [parameter(Mandatory=$true)]
        [string]$KeyVault,
        [bool]$ReturnFullCertificateArray = $false
    )

    $certs = Get-AzKeyVaultCertificate -VaultName $KeyVault
    
    $friendlyCerts = @()

    if($ReturnFullCertificateArray -eq $false)
    {        
        foreach($cert in $certs)
        {
            $friendlyCerts += "$($cert.Name)"
        }

        return $friendlyCerts
    }
    else
    {
        return $certs
    }

}

function Invoke-FileBrowser
{
    try
    {
        Add-Type -AssemblyName System.Windows.Forms
        $Browser = New-Object System.Windows.Forms.OpenFileDialog

        $PromptSuccess = $Browser.ShowDialog()
        
        if($PromptSuccess -eq "OK")
        {
            $SelectedFile = $Browser.FileName
            return $SelectedFile
        }
    }
    catch
    {
        Write-Host "Error displaying filebrowser"
        return $null
    }
}

function Get-ExportablePFX
{
    $Path = Get-Location
    Clear-Host
    Write-Host "Working..."
    $CertificateOptions = Get-AvailableCertArray -KeyVault $keyVaultName
    Clear-Host
    $SelectedCertificate = Show-OptionPicker -Options $CertificateOptions
    $Password = Get-RandomPassword
    
    try
    {
        $KVSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SelectedCertificate -AsPlainText
        $Bytes = [System.Convert]::FromBase64String($KVSecret)
        $Collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $Collection.Import($Bytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $CollectionExport = $Collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $Password)

        New-Item -ItemType Directory -Path "$($Path)\$($SelectedCertificate)"

        [System.IO.File]::WriteAllBytes("$($Path)\$($SelectedCertificate)\$($SelectedCertificate).pfx", $CollectionExport)
        $Password >> "$($Path)\$($SelectedCertificate)\$($SelectedCertificate).pwd.txt"

        Clear-Host
        Write-Host "Certificate has been exported successfully to: $($Path)\$($SelectedCertificate)..."
        Write-Host ""
        Write-Host "Returning to main menu..."
        Start-Sleep -S 10
    }
    catch
    {
        Write-Host "Failed to obtain certificate from Azure Keyvault"
    }

}

function Show-Certificates
{
    try 
    {
        Clear-Host
        Write-Host "Working..."
        $CertificateOptions = Get-AvailableCertArray -KeyVault $keyVaultName
        $i = 1
        foreach ($c in $CertificateOptions)
        {
            Write-Host "[$($i)] $c"
            $i++
        }
        Write-Host -NoNewLine 'Press [any] key to return...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') 
    }
    catch 
    {
        Write-Host "Unable to obtain list of available certificates... Returning"
        Start-Sleep -S 5
        break
    }
}

function Find-Certificates
{
    Clear-Host
    Write-Host "Search for a certificate..."
    $Query = Read-Host -Prompt "[Input]"
    Clear-Host
    Write-Host Working...
    $CertificateOptions = Get-AvailableCertArray -KeyVault $keyVaultName

    $matchingDNSNames = Search-DNSMatch -userInput $Query -dnsNames $CertificateOptions

    if ($matchingDNSNames.Count -eq 0) 
    {
        Clear-Host
        Write-Host "No matching DNS names found... Returning..."
        Start-Sleep -S 5
        break
    }
    else 
    {
        $FullCertArray = Get-AvailableCertArray -KeyVault $keyVaultName -ReturnFullCertificateArray $true
        Clear-Host
        Write-Host "Certificates with partial or full match to '$($Query)' were found:"
        Write-Host ""
        foreach($dnsname in $matchingDNSNames)
        {
            foreach ($cert in $FullCertArray)
            {
                if($cert.Name -eq $dnsname) 
                {
                    Write-Host "===================="
                    Write-Host "CN: $($cert.Name)"
                    Write-Host "Expires: $($cert.Expires)"
                    Write-Host "Created: $($cert.Created)"
                    Write-Host "Enabled: $($cert.Enabled)"
                    Write-Host "===================="
                    Write-Host ""
                }
            }
        }
        Write-Host "At this time, this search feature is just intended to allow you to easily find if a certificate exists. To perform an operation, return to the main menu..."
        Write-Host ""
        Write-Host -NoNewLine 'Press [any] key to return...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

Function Get-CSR
{
    try
    {
        $Path = Get-Location
        Clear-Host
        Write-Host "Working..."
        $CertificateOptions = Get-AvailableCertArray -KeyVault $keyVaultName
        Clear-Host
        Write-Host "Please pick a certificate to cycle the certificate version and download a CSR..."
        $SelectedCertificate = Show-OptionPicker -Options $CertificateOptions
        $FQDN = $SelectedCertificate -replace "\-", "."

        $Policy = New-AzKeyVaultCertificatePolicy -SubjectName "CN=$FQDN,$($CertificateAttributes)" -ValidityInMonths 12 -IssuerName Unknown -EmailAtNumberOfDaysBeforeExpiry 14
        $CSR = Add-AzKeyVaultCertificate -VaultName $keyVaultName -Name $SelectedCertificate -CertificatePolicy $Policy

        New-Item -ItemType Directory -Path "$($Path)\$($SelectedCertificate)"

        Write-Output "-----BEGIN CERTIFICATE REQUEST-----" >> "$($Path)\$($SelectedCertificate)\$($SelectedCertificate).csr.txt"
        $CSR.CertificateSigningRequest >> "$($Path)\$($SelectedCertificate)\$($SelectedCertificate).csr.txt"
        Write-Output "-----END CERTIFICATE REQUEST-----" >> "$($Path)\$($SelectedCertificate)\$($SelectedCertificate).csr.txt"

        Clear-Host
        Write-Host "CSR has been exported successfully to: $($Path)\$($SelectedCertificate).csr.txt..."
        Write-Host ""
        Write-Host "Returning to main menu..."
        Start-Sleep -S 10
    }
    catch
    {
        Write-Host "issue generating CSR"
        break
    }
}

function Merge-PEMCertificate
{

    Clear-Host
    Write-Host "Pick a certificate that you'd like to merge in a CA signed request for:"

    $SelectedFile = Invoke-FileBrowser

    $Options = Get-AvailableCertArray -KeyVault $keyVaultName
    $SelectedCertificate = Show-OptionPicker -Options $Options
    Write-Host "Working..."

    if($null -ne $SelectedFile)
    {
        if($SelectedFile -match '\.(pfx|pem)$')
        {
            Clear-Host
            az keyvault certificate pending merge --vault-name $keyVaultName --name $SelectedCertificate --file $SelectedFile
            Write-Host "Merge operation completed"
            Write-Host "Returning to menu..."
            Start-Sleep -S 10
        }
        else
        {
            Clear-Host
            Write-Host "The certificate that you provided isn't the correct format. Please provide a PFX or PEM CA-signed certificate. Returning..."
            Start-Sleep -S 10
        }
    }
    else
    {
        Clear-Host
        Write-Host "There was an issue obtaining the file that you selected, or displaying the prompt. Returning..."
        Start-Sleep -S 10
        break
    }

}

while($true)
{
	
    Clear-Host
    Write-Host "A tool for the SRE team to perform various certificate based operations"

    $options = @("List Certificates", "Search for a Certificate", "Export PFX", "Merge PEM", "Generate CSR")
    $selectedOption = Show-OptionPicker -Options $options

    switch -exact($selectedOption)
    {
        "List Certificates"
        {
            Show-Certificates
        }
        "Search for a Certificate"
        {
            Find-Certificates
        }
        "Export PFX"
        {
            Get-ExportablePFX
        }
        "Merge PEM"
        {
            Merge-PEMCertificate
        }
        "Generate CSR"
        {
            Get-CSR
        }
        default
        {
            break
        }
    }

}
