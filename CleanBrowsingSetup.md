# **Set DNS Through Installing Win 10 CleanBrowsing App**

- Install the app
- Configure custom filter using ID
- Enable password protection
- Enable uninstallation protection
- Blocking internet options setting should not be needed since that is covered through policy management below

# Setting up Dynamic DNS for Public IP Sharing with CleanBrowsing

To update your DNS provider with a dynamic IP address using a URL like `https://my.cleanbrowsing.org/dynip/abc123`, you typically need to automate the process of sending a request to that URL. This request informs your DNS provider of your current IP address, allowing the provider to update the DNS records accordingly. Here's how you can achieve this on different platforms:

### Windows

You can use a scheduled task in Windows to run a PowerShell script that sends a request to the URL.

### Step 1: Create PowerShell Script

1. Open Notepad or any text editor.
2. Paste the following PowerShell code:
    
    ```powershell
    # Log file path
    $logFilePath = "C:\Scripts\Logs\DynamicDNS.txt"
    
    # Function to write log messages
    function Write-Log {
        param(
            [string]$Message
        )
    
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogMessage = "$Timestamp - $Message"
        $LogMessage | Out-File -FilePath $logFilePath -Append
    }
    
    # Write log message indicating script start
    Write-Log "Script started."
    
    try {
        # Invoke web request to retrieve dynamic IP address
        $response = Invoke-WebRequest -Uri "https://my.cleanbrowsing.org/dynip/abc123" -UseBasicParsing
        $ipAddress = $response.Content
    
        # Log the retrieved IP address
        Write-Log "Retrieved IP address: $ipAddress"
    
        # Add your additional logic here if needed
        
        Write-Log "Script completed successfully."
    }
    catch {
        # Write exception details to log if an error occurs
        Write-Log "Error occurred: $_"
    }
    
    ```
    
3. Save the file with a `.ps1` extension, e.g., `CleanBrowsingDynamicDNS.ps1`, to a known location like `C:\Scripts\`.
4. Set permissions on the file to deny standard users access

### Step 2: Create Scheduled Task

1. Open Task Scheduler (`taskschd.msc`).
2. Select "Create Task…" and give it a name, e.g., "Dynamic DNS Updates".
3. Set the trigger as on workstation lock of any user
4. Make sure it is set to “Run whether user is logged on or not”. You may need to not use the basic task flow for this.
5. Configure the task for Windows 10 in the dropdown
6. Set to run with highest privileges
7. Under Conditions, set it to “Start only if the following network connection is available” and select Any connection
8. For the action, select "Start a program," then browse to the PowerShell executable (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).
9. In the "Add arguments" field, enter `-ExecutionPolicy Bypass -File "C:\Scripts\CleanBrowsingDynamicDNS.ps1"`.
10. Complete the wizard.

# Block DOH (DNS over HTTPS)

**Note:** CleanBrowsing likely already blocks many DOH domains. The step here involves blocking IP addresses which could be used to access DOH in browsers etc.

### Windows

You can use a scheduled task in Windows to run a PowerShell script that dynamically adds block rules to the firewall based on a public IP blocklist

### Step 1: Create PowerShell Script

1. Open Notepad or any text editor.
2. Paste the following PowerShell code:
    
    ```powershell
    # Define URLs to fetch IP addresses from
    $ipv4Url = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt"
    $ipv6Url = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt"
    $logFile = "C:\Scripts\Logs\BlockDOH.txt"
    
    # Define IP addresses to exclude from blocking so that you can still use CleanBrowsing
    $excludeIPs = @('185.228.168.10')
    
    # Function to fetch and parse IP addresses from URLs
    function Get-IPsFromUrl {
        param (
            [string]$Url
        )
        $content = Invoke-WebRequest -Uri $Url -UseBasicParsing
        $ips = $content.Content -split "`n" | ForEach-Object {
            if ($_ -match '^\s*([0-9a-f:.]+)') { $matches[1] }
        }
        return $ips
    }
    
    # Fetch IP addresses
    $ipv4Addresses = Get-IPsFromUrl -Url $ipv4Url
    $ipv6Addresses = Get-IPsFromUrl -Url $ipv6Url
    
    # Combine IPv4 and IPv6 addresses
    $allIPs = $ipv4Addresses + $ipv6Addresses
    
    # Ensure the log file directory exists
    $dir = Split-Path -Path $logFile
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    
    # Get existing firewall rules
    $existingRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "BlockDoH*" } | Select-Object -ExpandProperty DisplayName
    
    # Add firewall rules for new IP addresses, excluding specified IPs
    foreach ($ip in $allIPs) {
        if ($ip -in $excludeIPs) {
            "Skipping excluded IP $ip" | Out-File -FilePath $logFile -Append
            continue
        }
    
        $ruleName = "BlockDoH_$ip"
        if ($ruleName -notin $existingRules) {
            # Adding rule to block the IP
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ip -Protocol Any
            "Added firewall rule to block $ip" | Out-File -FilePath $logFile -Append
        }
        else {
            "Rule for $ip already exists." | Out-File -FilePath $logFile -Append
        }
    }
    
    "Firewall rules update completed." | Out-File -FilePath $logFile -Append
    ```
    
3. Save the file with a `.ps1` extension, e.g., `BlockDOH.ps1`, to a known location like `C:\Scripts\`.
4. Set permissions on the file to deny standard users access explicitly.

### Step 2: Create Scheduled Task

1. Open Task Scheduler (`taskschd.msc`).
2. Select "Create Task…" and give it a name, e.g., "Block DOH".
3. Set the trigger as Monthly on the first day or something similar
4. Make sure it is set to “Run whether user is logged on or not”. You may need to not use the basic task flow for this.
5. Configure the task for Windows 10 in the dropdown
6. Set to run with highest privileges
7. Under Conditions, set it to “Start only if the following network connection is available” and select Any connection
8. Under Settings, leave all the defaults, except check “Run task as soon as possible after a scheduled start is missed”
9. For the action, select "Start a program," then browse to the PowerShell executable (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).
10. In the "Add arguments" field, enter `-ExecutionPolicy Bypass -File "C:\Scripts\BlockDOH.ps1"`.
11. Complete the wizard.
12. Feel free to manually trigger the script on the first run to get the initial IPs blocked

# Block DOT (DNS over TLS)

### **Block DOT Using Windows Defender Firewall**

Creating outbound rules in the Windows Defender Firewall to block port 853 can effectively prevent applications from using DNS over TLS. Here’s a basic outline of how to do this:

1. **Open Windows Defender Firewall with Advanced Security**: Search for it in the Start menu and open it.
2. **Create a New Outbound Rule**: Navigate to **`Outbound Rules`** and choose **`New Rule`**.
3. **Select Rule Type**: Choose **`Port`** as the rule type and click **`Next`**.
4. **Specify Port**: Select **`TCP`** and specify **`853`** as the port number to block, then click **`Next`**.
5. **Block the Connection**: Choose **`Block the connection`** and proceed.
6. **Profile Application**: Apply the rule to Domain, Private, and Public profiles as necessary.
7. **Name the Rule**: Give your rule a meaningful name, such as “Block DNS over TLS”, and finish the wizard.

# API Setup for Windows 10

1. **Create four text files** for users to edit and make sure the Users group has permission to edit the files:
    - `AddToWhitelist.txt` (Delayed)
    - `RemoveFromWhitelist.txt`  (Immediate)
    - `AddToBlocklist.txt`  (Immediate)
    - `RemoveFromBlocklist.txt`  (Delayed)
2. **Write two PowerShell scripts** that processes these files. The reason for two separate files is because one script will be ran immediately, and the other will be ran on a delay. There is an option to immediately remove certain domains from the blocklist. Currently this is configured to allow removal of [google.com](http://google.com) from the blocklist immediately because the Captcha service is hosted on google.com and breaks a lot of sites when google.com is blocked. There could be other uses for this as well.

**DNSManagementImmediate.ps1**

```powershell
# Log file path
$logFilePath = "C:\Scripts\Logs\DNSManagement.txt"

# Function to write log messages
function Write-Log {
    param(
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp - $Message"
    $LogMessage | Out-File -FilePath $logFilePath -Append
}

Write-Log "Script for immediate actions started."

try {
    # Function to send API requests
    function Send-APIRequest {
        param (
            [string]$Action,
            [string]$Domain
        )
        $apiKey = "***YOUR API KEY HERE***"
        $uri = "https://my.cleanbrowsing.org/api?apikey=$apiKey&action=$Action&domain_name=$Domain"

        Write-Log "Invoking API request: $Action for domain: $Domain"
        $response = Invoke-RestMethod -Uri $uri -Method Get
        Write-Log "API response: $($response | ConvertTo-Json -Depth 5)"
    }

    # Function to process actions based on file contents
    function Process-Actions {
        param (
            [string]$FilePath,
            [string]$Action
        )
        if (Test-Path $FilePath) {
            $domains = Get-Content $FilePath
            foreach ($domain in $domains) {
                Write-Log "Processing action: $Action for domain: $domain"
                Send-APIRequest -Action $Action -Domain $domain
            }
            # Clear file after processing
            Clear-Content $FilePath
        }
    }

    # Function to immediately remove specific domains from the blocklist if listed
    function Unblock-SpecificDomains {
        $blockedDomainsPath = "C:\Scripts\RemoveFromBlocklist.txt"
        $permissibleDomains = @("google.com") # Extendable list
        if (Test-Path $blockedDomainsPath) {
            $domainsToUnblock = Get-Content $blockedDomainsPath
            foreach ($domain in $domainsToUnblock) {
                if ($domain -in $permissibleDomains) {
                    Write-Log "Approving immediate blocklist removal for domain: $domain"
                    Send-APIRequest -Action "blocklist/delete" -Domain $domain
                }
            }
            # Optionally clear file after processing
            Clear-Content $blockedDomainsPath
        }
    }

    # Process actions for different files
    Process-Actions -FilePath "C:\Scripts\RemoveFromWhitelist.txt" -Action "whitelist/delete"
    Process-Actions -FilePath "C:\Scripts\AddToBlocklist.txt" -Action "blocklist/add"
    
    # Check and approve specific domains immediately
    Unblock-SpecificDomains

    Write-Log "Script for immediate actions completed successfully."
}
catch {
    Write-Log "Error occurred: $_"
}

```

**DNSManagementDelayed.ps1**

```powershell
# Log file path
$logFilePath = "C:\Scripts\Logs\DNSManagement.txt"

# Function to write log messages
function Write-Log {
    param(
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp - $Message"
    $LogMessage | Out-File -FilePath $logFilePath -Append
}

Write-Log "Script for immediate actions started."

try {
    # Function to send API requests
    function Send-APIRequest {
        param (
            [string]$Action,
            [string]$Domain
        )
        $apiKey = "***YOUR API KEY HERE***"
        $uri = "https://my.cleanbrowsing.org/api?apikey=$apiKey&action=$Action&domain_name=$Domain"

        Write-Log "Invoking API request: $Action for domain: $Domain"
        $response = Invoke-RestMethod -Uri $uri -Method Get
        Write-Log "API response: $($response | ConvertTo-Json -Depth 5)"
    }

    # Function to process actions based on file contents
    function Process-Actions {
        param (
            [string]$FilePath,
            [string]$Action
        )
        if (Test-Path $FilePath) {
            $domains = Get-Content $FilePath
            foreach ($domain in $domains) {
                Write-Log "Processing action: $Action for domain: $domain"
                Send-APIRequest -Action $Action -Domain $domain
            }
            # Clear file after processing
            Clear-Content $FilePath
        }
    }

    # Process actions for different files
    Process-Actions -FilePath "C:\Scripts\AddToWhitelist.txt" -Action "whitelist/add"
    Process-Actions -FilePath "C:\Scripts\RemoveFromBlocklist.txt" -Action "blocklist/delete"

    Write-Log "Script for immediate actions completed successfully."
}
catch {
    Write-Log "Error occurred: $_"
}

```

### Save the Scripts:

1. Save this scripts to a location accessible by the system (e.g., `C:\Scripts\DNSManagementImmediate.ps1` and `C:\Scripts\DNSManagementDelayed.ps1` )
2. Set permissions on the files to deny any standard user accounts Modify and below permissions. This will prevent modification and reading of the API key. It also prevents on demand execution of the file. Admin accounts are part of the Users group, so don’t use that group to deny permissions.

### Schedule Immediate Script with Task Scheduler

1. **Open Task Scheduler** and create a new task (not basic task).
2. Set the task to **Run whether the user is logged on or not** and with **highest privileges**.
3. Configure the task for Windows 10 in the dropdown
4. **Trigger:** On workstation lock of any user
5. **Conditions:** Network ⇒ Start only if the following network connection is available: “Any connection”
6. **Action:** Set the action to start the PowerShell script.
    - Program/script: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
    - Add arguments: `-ExecutionPolicy Bypass -File "C:\Scripts\DNSManagementImmediate.ps1"`
7. **Conditions and Settings:** Adjust as needed for your environment.

### Schedule Delayed Script with Task Scheduler

1. **Open Task Scheduler** and create a new task (not basic task).
2. Set the task to **Run whether the user is logged on or not** and with **highest privileges**.
3. Configure the task for Windows 10 in the dropdown
4. **Trigger:** On workstation lock of any user with a **4hr delay**
5. **Conditions:** Network ⇒ Start only if the following network connection is available: “Any connection”
6. **Action:** Set the action to start the PowerShell script.
    - Program/script: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
    - Add arguments: `-ExecutionPolicy Bypass -File "C:\Scripts\DNSManagementDelayed.ps1"`
7. **Conditions and Settings:** Adjust as needed for your environment.

# Install Certificate to fix HTTPS Warnings

[https://cleanbrowsing.org/help/docs/cleanbrowsing-root-ca/](https://cleanbrowsing.org/help/docs/cleanbrowsing-root-ca/)
