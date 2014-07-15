#  .ExternalHelp Posh-Shodan.Help.xml
function Set-ShodanAPIKey
{
    [CmdletBinding()]
    Param
    (
        # VirusToral API Key.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $APIKey,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [securestring]$MasterPassword

    )

    Begin
    {}
    Process
    {
        write-verbose -Message "Setting the env variable `$Global:ShodanAPIKey with the key."
        $Global:ShodanAPIKey = $APIKey

        $SecureKeyString = ConvertTo-SecureString -String $APIKey -AsPlainText -Force
        
        # Generate a random secure Salt
        $SaltBytes = New-Object byte[] 32
        $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $RNG.GetBytes($SaltBytes)

        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $EncryptedString = $SecureKeyString | ConvertFrom-SecureString -key $KeyBytes

        $FolderName = 'Posh-Shodan'
        $ConfigName = 'api.key'
        $saltname   = 'salt.rnd'
        
        if (!(Test-Path -Path "$($env:AppData)\$FolderName"))
        {
            Write-Verbose -Message 'Seems this is the first time the config has been set.'
            Write-Verbose -Message "Creating folder $("$($env:AppData)\$FolderName")"
            New-Item -ItemType directory -Path "$($env:AppData)\$FolderName" | Out-Null
        }
        
        Write-Verbose -Message "Saving the information to configuration file $("$($env:AppData)\$FolderName\$ConfigName")"
        "$($EncryptedString)"  | Set-Content  "$($env:AppData)\$FolderName\$ConfigName" -Force
        Set-Content -Value $SaltBytes -Encoding Byte -Path "$($env:AppData)\$FolderName\$saltname" -Force
    }
    End
    {}
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Read-ShodanAPIKey
{
    [CmdletBinding()]

    Param
    (

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [securestring]$MasterPassword
    )

    Begin
    {
        # Test if configuration file exists.
        if (!(Test-Path -Path "$($env:AppData)\Posh-Shodan\api.key"))
        {
            throw 'Configuration has not been set, Set-ShodanAPIKey to configure the API Keys.'
        }
    }
    Process
    {
        Write-Verbose -Message "Reading key from $($env:AppData)\Posh-Shodan\api.key."
        $ConfigFileContent = Get-Content -Path "$($env:AppData)\Posh-Shodan\api.key"
        Write-Debug -Message "Secure string is $($ConfigFileContent)"

        $SaltBytes = Get-Content -Encoding Byte -Path "$($env:AppData)\Posh-Shodan\salt.rnd" 
        $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList 'user', $MasterPassword

        # Derive Key, IV and Salt from Key
        $Rfc2898Deriver = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $Credentials.GetNetworkCredential().Password, $SaltBytes
        $KeyBytes  = $Rfc2898Deriver.GetBytes(32)

        $SecString = ConvertTo-SecureString -Key $KeyBytes $ConfigFileContent

        # Decrypt the secure string.
        $SecureStringToBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecString)
        $APIKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SecureStringToBSTR)

        # Set session variable with the key.
        Write-Verbose -Message "Setting key $($APIKey) to variable for use by other commands."
        $Global:ShodanAPIKey = $APIKey
        Write-Verbose -Message 'Key has been set.'
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanAPIInfo
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                  ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', @{'key'= $APIKey})
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/api-info')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.APIKey.Info')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanService
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', @{'key'= $APIKey})
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/shodan/services')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.Services')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanHostService
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Direct')]
        [string]
        $IPAddress,

        # All historical banners should be returned.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [switch]
        $History,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        $Body = @{'key'= $APIKey; 'ip' = $IPAddress}

        if ($History)
        {
            $Body.add('history','True')
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]"https://api.shodan.io/shodan/host/$($IPAddress)")

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.Host.Info')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Search-ShodanHost
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
       # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials,

         # Text to query for.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Query = '',

        #  Find devices located in the given city. It's best combined with the
        # 'Country' filter to make sure you get the city in the country you 
        # want (city names are not always unique).
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $City,

        # Narrow results down by country.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Country,

        # Latitude and longitude.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Geo,

        # Search for hosts that contain the value in their hostname.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Hostname,
        
        # Limit the search results to a specific IP or subnet. It uses CIDR 
        # notation to designate the subnet range.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Net,

        # Specific operating systems. Common possible values are: windows,
        # linux and cisco.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $OS,

        # Search the HTML of the website for the given value.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$HTML,

        # Find devices based on the upstream owner of the IP netblock.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$ISP,

        # The network link type. Possible values are: "Ethernet or modem", 
        # "generic tunnel or VPN", "DSL", "IPIP or SIT", "SLIP", "IPSec or
        # "GRE", "VLAN", "jumbo Ethernet", "Google", "GIF", "PPTP", "loopback",
        # "AX.25 radio modem".
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [ValidateSet( 'Ethernet or modem', 'generic tunnel or VPN', 'DSL', 
            'IPIP or SIT', 'SLIP', 'IPSec or GRE', 'VLAN', 'jumbo Ethernet',
            'Google', 'GIF', 'PPTP', 'loopback', 'AX.25 radio modem')]
        [string[]]$Link,

        #Find NTP servers that had the given IP in their monlist.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$NTP_IP,

        # Find NTP servers that return the given number of IPs in the initial monlist response.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$NTP_IP_Count,

        # Find NTP servers that had IPs with the given port in their monlist.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [int]$NTP_Port,

        # Whether or not more IPs were available for the given NTP server.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [switch]$NTP_More,

        # Find devices based on the owner of the IP netblock.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Org,

        # Filter using the name of the software/ product; ex: product:Apache
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Product,

        # Filter the results to include only products of the given version; ex: product:apache version:1.3.37
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Version,

        # Search the title of the website.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Title,

        # Port number  to narrow the search to specific services.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Port,

        # Limit search for data that was collected before the given date in
        # format day/month/year.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Before,

        # Limit search for data that was collected after the given date in
        # format day/month/year.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$After,

        # The page number to page through results 100 at a time. Overrides the
        # "offset" and "limit" parameters if they were provided (default: 1)
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [int]$Page,

        # The positon from which the search results should be returned (default: 0)
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [int]$Offset,

        # The number of results to be returned default(100)
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [int]$Limit,

        # True or False; whether or not to truncate some of the larger fields (default: True)
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [bool]$Minify = $true,

        # A comma-separated list of properties to get summary information on. Property names 
        # can also be in the format of "property:count", where "count" is the number of facets
        # that will be returned for a property (i.e. "country:100" to get the top 100 countries
        # for a search query).
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]$Facets

    )

    Begin
    {
        if (!(Test-Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

         # Create the query string to execute.
        if ($City) {$Query += " city:'$($City.Trim())'"}

        if ($Country) {$Query += " country_name:`'$($Country.Trim())`'"}

        if ($Geo) {$Query += " geo:$($Geo.Trim())"}

        if ($Hostname) {$Query += " hostname:$($Hostname.Trim())"}

        if ($Net) {$Query += " net:$($Net.Trim())"}

        if ($OS) {$Query += " os:$($OS.Trim())"}

        if ($Port) {$Query += " port:$($Port.Trim())"}

        if ($Before) {$Query += " before:$($Before.Trim())"}

        if ($After) {$Query += " after:$($After.Trim())"}

        if ($HTML) {$Query += " html:$($HTML.Trim())"}

        if ($ISP) {$Query += " isp:`'$($ISP.Trim())`'"}

        if ($Link) {$Query += " link:$($Link.join(','))"}

        if ($Org) {$Query += " org:$($Org.Trim())"}

        if ($NTP_IP) {$Query += " ntp.ip:$($NTP_IP.Trim())"}

        if ($NTP_IP_Count) {$Query += " ntp.ip_count:$($NTP_IP_Count.Trim())"}

        if ($NTP_More) {$Query += ' ntp.more:True'}

        if ($NTP_Port) {$Query += " ntp.port:$($NTP_Port.Trim())"}

        if ($Title) {$Query += " title:$($Title.Trim())"}

        if ($Version) {$Query += " version:$($Version.Trim())"}

        if ($Product) {$Query += " product:$($Product.Trim())"}

        # Set propper request parameters.
        $Body = @{'key'= $APIKey; 'query'= $Query}

        if ($Page)
        {
            $Body.Add('page', $Page)
        }

        if ($Offset)
        {
            $Body.Add('offset',$Offset)
        }

        if ($Limit)
        {
            $Body.Add('limit',$Limit)
        }

        if ($Minify)
        {
            $Body.Add('minify','True')
        }
        else
        {
            $Body.Add('minify','False')
        }

        if ($Facets)
        {
            $Body.Add('facets',$Facets)
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/shodan/host/search')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
       
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            if ($ReturnedObject.total -ne 0)
            {
                $matches = @()
                foreach($match in $ReturnedObject.matches)
                {
                    $match.pstypenames.insert(0,'Shodan.Host.Match')
                    $matches = $matches + $match
                }

                $properties = [ordered]@{
                                'Total' = $ReturnedObject.total;
                                'Matches' = $matches; 
                                'Facets' = $ReturnedObject.facets
                              }

                $searchobj = [pscustomobject]$properties
                $searchobj.pstypenames.insert(0,'Shodan.Host.Search')
                $searchobj
            }
            else
            {
                Write-Warning -Message 'No matches found.'
            }
        }
    }
    End 
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Measure-ShodanHost
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
       # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]$ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials,

         # Text to query for.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Query = '',

        #  Find devices located in the given city. It's best combined with the
        # 'Country' filter to make sure you get the city in the country you 
        # want (city names are not always unique).
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $City,

        # Narrow results down by country.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Country,

        # Latitude and longitude.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Geo,

        # Search for hosts that contain the value in their hostname.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Hostname,
        
        # Limit the search results to a specific IP or subnet. It uses CIDR 
        # notation to designate the subnet range.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Net,

        # Specific operating systems. Common possible values are: windows,
        # linux and cisco.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $OS,

        # Search the HTML of the website for the given value.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $HTML,

        # Find devices based on the upstream owner of the IP netblock.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $ISP,

        # The network link type. Possible values are: "Ethernet or modem", 
        # "generic tunnel or VPN", "DSL", "IPIP or SIT", "SLIP", "IPSec or
        # "GRE", "VLAN", "jumbo Ethernet", "Google", "GIF", "PPTP", "loopback",
        # "AX.25 radio modem".
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [ValidateSet('Ethernet or modem', 'generic tunnel or VPN', 'DSL', 
                     'IPIP or SIT', 'SLIP', 'IPSec or GRE', 'VLAN', 
                     'jumbo Ethernet','Google', 'GIF', 'PPTP', 'loopback',
                     'AX.25 radio modem')]
        [string[]]
        $Link,

        #Find NTP servers that had the given IP in their monlist.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]
        $NTP_IP,

        # Find NTP servers that return the given number of IPs in the initial monlist response.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $NTP_IP_Count,

        # Find NTP servers that had IPs with the given port in their monlist.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]
        $NTP_Port,

        # Whether or not more IPs were available for the given NTP server.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [switch]
        $NTP_More,

        # Find devices based on the owner of the IP netblock.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Org,

        # Filter using the name of the software/ product; ex: product:Apache
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Product,

        # Filter the results to include only products of the given version; ex: product:apache version:1.3.37
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Version,

        # Search the title of the website.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Title,

        # Port number  to narrow the search to specific services.
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
        ParameterSetName = 'Direct')]
        [string]
        $Port,

        # Limit search for data that was collected before the given date in
        # format day/month/year.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Before,

        # Limit search for data that was collected after the given date in
        # format day/month/year.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $After,

        # The page number to page through results 100 at a time. Overrides the
        # "offset" and "limit" parameters if they were provided (default: 1)
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]
        $Page,

        # The positon from which the search results should be returned (default: 0)
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]
        $Offset,

        # The number of results to be returned default(100)
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]
        $Limit,

        # True or False; whether or not to truncate some of the larger fields (default: True)
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [bool]
        $Minify = $true,

        # A comma-separated list of properties to get summary information on. Property names 
        # can also be in the format of "property:count", where "count" is the number of facets
        # that will be returned for a property (i.e. "country:100" to get the top 100 countries
        # for a search query).
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Facets

    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

         # Create the query string to execute.
        if ($City) {$Query += " city:'$($City.Trim())'"}

        if ($Country) {$Query += " country_name:`'$($Country.Trim())`'"}

        if ($Geo) {$Query += " geo:$($Geo.Trim())"}

        if ($Hostname) {$Query += " hostname:$($Hostname.Trim())"}

        if ($Net) {$Query += " net:$($Net.Trim())"}

        if ($OS) {$Query += " os:$($OS.Trim())"}

        if ($Port) {$Query += " port:$($Port.Trim())"}

        if ($Before) {$Query += " before:$($Before.Trim())"}

        if ($After) {$Query += " after:$($After.Trim())"}

        if ($HTML) {$Query += " html:$($HTML.Trim())"}

        if ($ISP) {$Query += " isp:`'$($ISP.Trim())`'"}

        if ($Link) {$Query += " link:$($Link -join ',')"}

        if ($Org) {$Query += " org:$($Org.Trim())"}

        if ($NTP_IP) {$Query += " ntp.ip:$($NTP_IP.Trim())"}

        if ($NTP_IP_Count) {$Query += " ntp.ip_count:$($NTP_IP_Count.Trim())"}

        if ($NTP_More) {$Query += ' ntp.more:True'}

        if ($NTP_Port) {$Query += " ntp.port:$($NTP_Port.Trim())"}

        if ($Title) {$Query += " title:$($Title.Trim())"}

        if ($Version) {$Query += " version:$($Version.Trim())"}

        if ($Product) {$Query += " product:$($Product.Trim())"}

        # Set request parameters.

        $Body = @{'key'= $APIKey; 'query'= $Query}

        if ($Page) {$Body.Add('page', $Page)}

        if ($Offset) {$Body.Add('offset',$Offset)}

        if ($Limit) {$Body.Add('limit',$Limit)}

        if ($Minify)
        {
            $Body.Add('minify','True')
        }
        else
        {
            $Body.Add('minify','False')
        }

        if ($Facets) {$Body.Add('facets',$Facets)}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/shodan/host/count')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
       
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.Host.Count')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanDNSResolve
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        # Comma-separated list of hostnames ro resolve."
        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Direct')]
        [string[]]
        $Hostname,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        $Body = @{'key'= $APIKey; 'hostnames' = ($Hostname -join ',')}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/dns/resolve')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.DNS.Resolve')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanDNSReverse
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        # List of IP Addresses to resolve
        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Direct')]
        [string[]]
        $IPAddress,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        $Body = @{'key'= $APIKey; 'hostnames' = ($IPAddress -join ',')}

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/dns/resolve')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.DNS.Resolve')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Get-ShodanMyIP
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials
    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', @{'key'= $APIKey})
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://api.shodan.io/tools/myip')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Search-ShodanExploit
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials,

        # list of properties to get summary information on.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [ValidateSet('author', 'platform', 'port', 'source', 'type')]
        [string[]]
        $Facets,

        # Text to query for.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Query,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]
        $Page,

        # CVE ID
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$CVE,

        # OpenSource Vulnerability Databse ID
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$OSVDB,

        # SecurityFocus BID Number
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$BID,

        # Microsoft Buletin (MS012-020)
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$MSB,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [ValidateSet('aix', 'asp', 'bsd', 'bsd/ppc', 'bsd/x86','bsdi/x86','cgi',
        'freebsd','freebsd/x86','freebsd/x86-64','generator','hardware', 'hp-ux', 
        'irix', 'jsp', 'linux', 'linux/amd64', 'linux/mips', 'linux/ppc', 'linux/sparc', 
        'linux/x86', 'linux/x86-64', 'minix', 'multiple', 'netbsd/x86', 'novell', 'openbsd', 
        'openbsd/x86', 'os-x/ppc', 'osx', 'php','plan9', 'qnx', 'sco', 'sco/x86', 
        'solaris', 'solaris/sparc', 'solaris/x86', 'tru64', 'ultrix', 'unix', 'unixware',
        'win32','win64','windows','arm','cfm')]
        [string]$Platform,

        # Param2 help description
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [ValidateSet('Local', 'Papers', 'Remote', 'Shellcode', 'WebApps', 'DoS')]
        [string]$Type,

        # The port number for the affected service if the exploit is remote.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [int]$Port,

        # The author of the exploit/ vulnerability.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$Author,

        #  When the exploit was released  format day/month/year..
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$Date,

        #  The description of the exploit, how it works and where it applies.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$Description,

        # The title or short description for the exploit if available.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]$Title
    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        # Build the query string with filters selected
         if ($CVE)
        {
            $Query += " cve:$($CVE.Trim())"
        }

        if ($OSVDB)
        {
            $Query += " osvdb:$($OSVDB.Trim())"
        }

        if ($BID)
        {
            $Query += " bid:$($BID.Trim())"
        }

        if ($MSB)
        {
            $Query += " msb:$($MSB.Trim())"
        }

        if ($Platform)
        {
            $Query += " platform:$($Platform.Trim())"
        }

        if ($Type)
        {
            $Query += " type:$($Type.Trim())"
        }
        
        if ($Port)
        {
            $Query += " port:$($Port)"
        }

        if ($Author)
        {
            $Query += " author:$($Author.Trim())"
        }

        if ($Date)
        {
            $Query += " date:$($Date.Trim())"
        }

        if ($Description)
        {
            $Query += " description:$($Description.Trim())"
        }

        if ($Title)
        {
            $Query += " title:$($Title.Trim())"
        }

        # Set base request body. 
        $Body = @{'key'= $APIKey; 'query' = $Query}
        
        if ($Facets)
        {
            $Body.Add('facets', ($Facets -join ','))
        }

        if ($Page)
        {
            $Body.Add('page', $Page)
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://exploits.shodan.io/api/search')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.Exploit.Search')
            $ReturnedObject
        }
    }
    End
    {
    }
}

#  .ExternalHelp Posh-Shodan.Help.xml
function Measure-ShodanExploit
{
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    Param
    (
        # Shodan developer API key
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $APIKey,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory=$true,
                   ParameterSetName = 'Proxy')]
        [string]
        $Proxy,
 
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Management.Automation.PSCredential]
        $ProxyCredential,

        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Switch]
        $ProxyUseDefaultCredentials,

        # list of properties to get summary information on.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [ValidateSet('author', 'platform', 'port', 'source', 'type')]
        [string[]]
        $Facets,

        # Text to query for.
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Proxy')]
        [Parameter(Mandatory=$false,
                   ParameterSetName = 'Direct')]
        [string]
        $Query
    )

    Begin
    {
        if (!(Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            throw 'No Shodan API Key has been specified or set.'
        }
        elseif ((Test-Path -Path variable:Global:ShodanAPIKey ) -and !($APIKey))
        {
            $APIKey = $Global:ShodanAPIKey
        }

        $Body = @{'key'= $APIKey; 'query' = $Query}
        
        if ($Facets)
        {
            $Body.Add('facets', ($Facets -join ','))
        }

        # Start building parameters for REST Method invokation.
        $Params =  @{}
        $Params.add('Body', $Body)
        $Params.add('Method', 'Get')
        $Params.add('Uri',[uri]'https://exploits.shodan.io/api/count')

        # Check if connection will be made thru a proxy.
        if ($PsCmdlet.ParameterSetName -eq 'Proxy')
        {
            $Params.Add('Proxy', $Proxy)

            if ($ProxyCredential)
            {
                $Params.Add('ProxyCredential', $ProxyCredential)
            }

            if ($ProxyUseDefaultCredentials)
            {
                $Params.Add('ProxyUseDefaultCredentials', $ProxyUseDefaultCredentials)
            }
        }

        # Check if we will be doing certificate pinning by checking the certificate thumprint.
        if ($CertificateThumbprint)
        {
            $Params.Add('CertificateThumbprint', $CertificateThumbprint)
        }
    }
    Process
    {
        $ReturnedObject = Invoke-RestMethod @Params
        if ($ReturnedObject)
        {
            $ReturnedObject.pstypenames.insert(0,'Shodan.Exploit.Count')
            $ReturnedObject
        }
    }
    End
    {
    }
}
