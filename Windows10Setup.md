# Windows 10 Enterprise

# Block Windows App Store

### Block Windows Store

1. **Open Group Policy Editor**:
    - Press **`Windows Key + R`** to open the Run dialog.
    - Type **`gpedit.msc`** and press Enter to launch the Local Group Policy Editor.
2. **Navigate to the Windows Store Policy**:
    - In the Group Policy Editor, navigate to **`Computer Configuration`** > **`Administrative Templates`** > **`Windows Components`** > **`Store`**.
3. **Disable the Store Application**:
    - Find the setting **`Turn off the Store application`**.
    - Double-click on it to open its configuration window.
4. **Configure the Setting**:
    - Select **`Enabled`** to disable access to the Windows Store.
    - Click **`Apply`** and then **`OK`** to save the changes.

# Prevent Installation of Unwanted Software Through AppLocker

**Note:** The reason this is needed is because there are many applications that can be installed to the users local profile without requiring admin permissions. Even though Chrome and Edge are locked down, a user could download an alternate browser to their local profile very easily.

Additionally, there is a more advanced solution called Windows Defender Application Control, and it is more powerful and secure, but it is harder to configure. I may consider using it in the future though.

### **1. Open the Local Security Policy Editor**

- Press **`Win + R`** to open the Run dialog.
- Type **`secpol.msc`** and press Enter.

### **2. Navigate to AppLocker**

- In the Local Security Policy window, expand the **`Application Control Policies`** node.
- Click on **`AppLocker`**. This displays AppLocker's overview and configuration options.

### **3. Configure AppLocker Properties (Optional)**

- Right-click on **`AppLocker`**, then select **`Properties`**.
- In the AppLocker Properties window, you can configure additional settings, like enforcement settings. These are optional at the start but can be configured as needed.

### **4. Create Default Rules**

For each rule type (Executables, Windows Installer Files, Script, and Packaged app Rules), you'll want to create default rules.

### For Executables:

- Right-click **`Executable Rules`** and choose **`Create Default Rules`**. Three default rules are created:
    1. Allow all users to run executables in the Windows folder.
    2. Allow all users to run executables in the Program Files folder.
    3. Allow members of the local Administrators group to run all executables.

### For Windows Installer Files:

- Right-click **`Windows Installer Rules`** and choose **`Create Default Rules`**. Similar default rules are created for installer packages.

### For Scripts and Packaged Apps:

- Repeat the process for **`Script Rules`** and **`Packaged app Rules`** if you want to control these types of applications as well.

### **5. Configure Rule Enforcement**

- Once the default rules are created, you need to enable rule enforcement.
- Right-click on **`Executable Rules`**, **`Windows Installer Rules`**, **`Script Rules`**, or **`Packaged app Rules`**, then select **`Properties`**.
- In the Enforcement tab, select **`Enforce rules`** for the rule types you want to enforce. You might start with Executables and Windows Installer Files.

### **6. Configure the Application Identity Service to Start Automatically**

Starting with Windows 10, the Application Identity service is now a protected process. As a result, you can no longer manually set the service **Startup type** to **Automatic** by using the Services snap-in. Try either of these methods instead:

- Open an elevated command prompt or PowerShell session and type then run:

```jsx
sc.exe config appidsvc start=auto
```

### **7. Test Your Configuration**

- To ensure everything is set up correctly, try running applications as both a standard user and an administrator. Verify that the rules work as expected.

### **8. Monitor and Adjust Rules**

- Use the AppLocker logs in Event Viewer (**`Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker`**) to monitor allowed and blocked applications.
- Adjust your rules based on operational needs and any issues encountered.

# Approving Executables Previously Blocked by AppLocker on a Delay

### Step 1: Prepare the PowerShell Script

Prepare the script that standard users can edit to specify installer paths. This script will read publisher info or hash from a file and apply an AppLocker policy to allow it.

```powershell
# Define the log file path
$logFilePath = "C:\Scripts\Logs\AppLocker.txt"

# Function to write log messages
function Write-Log {
    param(
        [string]$Message
    )
    Add-Content -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") - $Message" -Path $logFilePath
}

# Start of the script
Write-Log "Script started."

try {
    # Get the list of file paths from a file
    $filePath = "C:\Scripts\FilePaths.txt"
    $filePaths = Get-Content $filePath

    # Retrieve file information for each path
    $fileInfoList = $filePaths | ForEach-Object {
        Write-Log "Processing file: $_"
        Get-AppLockerFileInformation -Path $_
    }

    # Create AppLocker policy from the file information collected
    $policyXml = $fileInfoList | New-AppLockerPolicy -RuleType Publisher, Hash -User "Everyone" -Optimize -Xml

    # Merge the new policy with the existing local AppLocker policy
    $policyXml | Set-AppLockerPolicy -Merge

    Write-Log "New AppLocker policy merged with existing local policy."
}
catch {
    Write-Log "Error occurred: $_"
}
finally {
    # Clear the file paths from C:\Scripts\FilePaths.txt after processing
    Clear-Content -Path $filePath

    Write-Log "Cleared file paths from $filePath."
}

Write-Log "Script completed."

```

Ensure this script is saved in a location where standard users can edit the `FilePaths.txt` file but not the script itself, to prevent unauthorized modifications.

- Set permissions on the script file to deny Users “Modify” and below permissions

`FilePaths.txt` is a file with file paths separated by returns or new lines. No double quotes needed. An empty file will also mean no AppLocker commands will occur.

- Set permissions on the FilePaths.txt file to allow modification by the Users group.

### Step 3: Schedule the Script with Task Scheduler

1. **Open Task Scheduler** and create a new task (not basic task).
2. Set the task to **Run whether the user is logged on or not** and with **highest privileges**.
3. Configure the task for Windows 10 in the dropdown
4. **Trigger:** On workstation lock of any user
    - Set to 4hr delay
5. **Action:** Set the action to start the PowerShell script.
    - Program/script: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
    - Add arguments: `-ExecutionPolicy Bypass -File "C:\Scripts\AppLockerApprovePublisher.ps1"`
6. **Conditions and Settings:** Adjust as needed for your environment.

# **Set DNS Through Network Adapter Settings (IPv4 and IPv6) on Ethernet and Wi-Fi (ONLY if not using CleanBrowsing Win 10 app)**

- **For a Static Configuration:**
    - Open Network and Sharing Center > Change adapter settings.
    - Right-click your network connection > Properties.
    - Select Internet Protocol Version 4 (TCP/IPv4) or Internet Protocol Version 6 (TCP/IPv6) > Properties.
    - Set the DNS server addresses to your preferred IPv4 or IPv6 DNS servers.
    - If there are issues with IPv6, which is common, disable them on Ethernet and Wi-Fi under the adapter properties

# Using Group Policy to Restrict Network Settings

1. **Open Group Policy Editor:**
    - Press `Windows Key + R` to open the Run dialog.
    - Type `gpedit.msc` and press Enter to launch the Local Group Policy Editor.
2. **Navigate to Network Connection Settings:**
    - Go to `User Configuration` > `Administrative Templates` > `Network` > `Network Connections`.
3. **Apply Restrictions:**
    - Enable the policy `Prohibit access to properties of components of a LAN connection`. This setting should prevent users from accessing and changing properties of network connections, including DNS settings.
    - Enable `Prohibit access to properties of a LAN connection` . This might be too restrictive, but see if it works.
    - Enable `Prohibit adding and removing components for a LAN or remote access connection`
    - Enable `Prohibit configuration of VPN connection`

# Edge Hardening

## Download Templates

- Download the latest Edge policy templates from [Download Edge for Business (microsoft.com)](https://www.microsoft.com/en-us/edge/business/download)
    - You can click “Download Windows 64-bit Policy”
    - Extract the CAB file, and then the ZIP contents

## **Add the administrative template to an individual computer**

1. On the target computer, open *MicrosoftEdgePolicyTemplates* and go to **windows** > **admx**.
2. Copy the *msedge.admx* file to your Policy Definition template folder. (Example: C:\Windows\PolicyDefinitions)
3. In the *admx* folder, open the appropriate language folder. For example, if you're in the U.S., open the **en-US** folder.
4. Copy the *msedge.adml* file to the matching language folder in your Policy Definition folder. (Example: C:\Windows\PolicyDefinitions\en-US)
5. To confirm the files loaded correctly, open Local Group Policy Editor directly (Windows key + R and enter gpedit.msc) or open MMC and load the Local Group Policy Editor snap-in. If an error occurs, it's usually because the files are in an incorrect location.

## **Disabling DNS over HTTPS (DoH) in Microsoft Edge**

1. **Open Group Policy Editor**:
    - Press **`Win + R`**, type **`gpedit.msc`**, and press Enter.
2. **Navigate to Microsoft Edge Policies**:
    - In the Group Policy Editor, navigate to **`Computer Configuration`** > **`Administrative Templates`** > **`Microsoft Edge`**.
3. **Configure DnsOverHttpsMode**:
    - Find the policy named **`Control the mode of DNS-over-HTTPS`**.
    - Double-click on it to edit the policy settings.
    - Set the policy to **Enabled**. This might seem counterintuitive, but setting it to Enabled allows you to specify the mode.
    - In the options, set the mode to **`Off`** to disable DNS over HTTPS.
    - Click **`Apply`**, then **`OK`**.

## **Disabling the Built-in DNS Client in Microsoft Edge**

1. **Still within the Group Policy Editor and under Microsoft Edge policies**:
    - Look for a policy named **`Use built-in DNS client`**.
    - Double-click on it to edit the policy settings.
    - Set the policy to **Disabled**. This action will disable the built-in DNS client in Microsoft Edge.
    - Click **`Apply`**, then **`OK`**.

## **Disabling Extensions in Microsoft Edge**

1. **Open Group Policy Editor**:
    - Press **`Win + R`**, type **`gpedit.msc`**, and press Enter.
2. **Navigate to Microsoft Edge Policies**:
    - In the Group Policy Editor, navigate to **`Computer Configuration`** > **`Administrative Templates`** > **`Microsoft Edge`** > **`Extensions`**.
3. **Configure the Extension Policy**:
    - Find the policy named **`Control which extensions cannot be installed`**.
    - Double-click on it to edit the policy settings.
    - Set the policy to **Enabled**.
    - In the options section, you can specify a list of extensions that are allowed by entering their extension IDs. To disable all extensions, set an option to `*`.
    - Click **`Apply`**, then **`OK`**.

## **Test your policies**

On a target client device, open Microsoft Edge and go to **edge://policy** to see all policies that are applied. If you applied policy settings on the local computer, policies should appear immediately. You might need to close and reopen Microsoft Edge if it was open while you were configuring policy settings.

# Chrome Hardening

## Installing Administrative Templates

### **Step 1: Download Chrome Administrative Template**

1. **Download the Administrative Template:** First, you need to download the Chrome administrative template from the Chrome Enterprise page as a bundle. It contains the necessary files within it (https://chromeenterprise.google/browser/download/#download-browser).
2. **Extract the Contents:** The download will include a ZIP file containing the template and documentation. Extract the contents of this ZIP file to a folder.

### **Step 2: Add the Template to Group Policy**

1. **Open Group Policy Management:** Press **`Windows Key + R`**, type **`gpedit.msc`**, and press Enter to open the Local Group Policy Editor.
2. **Navigate to Administrative Templates:** Go to **`Local Computer Policy`** > **`Computer Configuration`** > **`Administrative Templates`**.
3. **Add/Remove Templates:** Right-click on **`Administrative Templates`**, and select **`Add/Remove Templates`**.
4. **Add the Chrome Template:** Click on **`Add`**, navigate to the location where you extracted the Chrome policy templates, and select the **`chrome.adm`** or **`chrome.admx`** file (depending on your version of Windows). If you're using the ADMX template, you should copy the ADMX file and its language folder (ADML) to the **`C:\Windows\PolicyDefinitions`** directory instead of using the Add/Remove Templates option.
5. **Close the Dialog:** After adding the template, click **`Close`** in the **`Add/Remove Templates`** dialog.

## **Configure Chrome Policy for Blocking Extensions and Allowing Some**

1. **Navigate to Chrome Policies:** Back in the Group Policy Editor, you'll now see a **`Google`** or **`Google Chrome`** section under **`Administrative Templates`** (the exact path might vary slightly based on the template version). Navigate to it.
2. **Enable Extension Allow List:** Look for a policy named `Configure extension installation allow list` 
    - **Enable the Policy:** Double-click the policy, set it to **`Enabled`**.
    
    **Specify the IDs in the options off all the extensions you want to allow:** In the options, add the IDs of the extensions you want to allow.
    
3. **Disable Extension Installation:** Look for a policy named something like **`Configure extension installation blocklist`**.
    - **Enable the Policy:** Double-click the policy, set it to **`Enabled`**.
    
    **Specify `*` to Block All Extensions:** In the options, add `*` to the list. This wildcard character blocks the installation of all new extensions not in the allow list.
    
4. **Apply the Policy:** Click **`OK`** or **`Apply`** to save the policy settings.

## **Configuring "Control SafeSites adult content filtering" in Google Chrome via Group Policy:**

To configure this policy, you will need to have administrative access to Group Policy Editor and the Chrome Administrative Template installed.

1. **Open Group Policy Editor**:
    - Press **`Win + R`**, type **`gpedit.msc`**, and press Enter.
2. **Navigate to Chrome Policies**:
    - Go to **`Computer Configuration`** > **`Administrative Templates`** > **`Google`** > **`Google Chrome`**.
3. **Locate and Configure the Policy**:
    - Find the **`Control SafeSites adult content filtering`** policy within the list.
    - Double-click on it to open the policy settings.
    - You can choose to **Enable** it to enforce SafeSites filtering or **Disable** it if you want to turn off the filtering. There may also be an option to leave the setting as **Not Configured**, which means the default behavior of Chrome (typically filtering disabled) will apply.
4. **Apply the Policy**:
    - After selecting your preferred option, click **`Apply`** and then **`OK`**.

## Disable DNS over HTTPS

### **Step 1: Open Group Policy Editor**

1. Press **`Win + R`** to open the Run dialog.
2. Type **`gpedit.msc`** and press Enter to launch the Local Group Policy Editor.

### **Step 2: Navigate to Chrome Policies**

1. In the Group Policy Editor, navigate to **`Computer Configuration`** > **`Administrative Templates`** > **`Google`** > **`Google Chrome`**.
    
    If you're managing user settings, you might instead go to **`User Configuration`** > **`Administrative Templates`** > **`Google`** > **`Google Chrome`**.
    

### **Step 3: Configure the "Controls the mode of DNS-over-HTTPS" Policy**

1. Find the policy named "Controls the mode of DNS-over-HTTPS" in the list.
2. Double-click the policy to edit it.
3. Set the policy to **Enabled**. This allows you to control the DoH settings.
4. In the options section, you will see a field to specify the mode. Enter **`Disable DNS-over-HTTPS`** to disable DNS-over-HTTPS.
5. Click **`Apply`**, then **`OK`** to save the changes.

### **Step 4: Disable Built-in DNS Client**

1. Find the policy named `Use built-in DNS client`
2. Set it to `Disabled`

## ALTERNATIVELY Force a Specific DNS over HTTPS URI

1. Find the policy named `Specify URI template of desired DNS-over-HTTPS resolver`
2. Enable the policy and set value to DoH URI
3. Find the policy `Controls the mode of DNS-over-HTTPS` and set it to `Enable DNS-over-HTTPS without insecure fallback` . This is considered the `secure` policy value.

## Force Google SafeSearch and YouTube Restricted Mode

1. Find the policy `Force Google SafeSearch` and enable it
2. Find the policy `Force minimum YouTube Restricted Mode` and enable it. Set it to Moderate or Strict

Note: These settings may be redundant if DNS is doing its job

## Testing Policies

Visit chrome://policy/  to see which policies are applied.

# BIOS

- Disable boot from USB in BIOS
- Set boot order to just boot to Windows
- Enable secure boot
- Add BIOS password
- Lock PC case so that CMOS battery cannot be removed, thus resetting the BIOS

# Already Considered

- Safe mode
    - Safe mode of a standard user carries with it the same restrictions of that standard user
- New user account creation
    - A standard user account cannot create new accounts
- Guest account
    - A standard user account cannot enable a guest account
