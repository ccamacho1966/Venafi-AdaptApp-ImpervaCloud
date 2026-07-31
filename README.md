# Imperva Cloud WAF
Adaptable Application driver for Imperva's cloud-based WAF (https://my.imperva.com) that makes full use of current Imperva APIs.

## Description
This adaptable application uses Imperva's API to gather site details and perform validation of custom certificates on the platform. Discovery requires that Venafi connect directly to the website port as there is no way to retrieve the public certificate via the API. Validation of legacy websites may also require direct connection (used as a fallback for when the API doesn't provide this information).

For Enterprise customers, sub-accounts can either be under a single consolidated "Imperva" device or separately with a device linked to each sub-account. Multiple API keys are not required to manage sub-accounts separately, but this is an option if your environment requires/prefers it as well.

## Installation
Upload the adaptable log driver file 'Imperva Cloud WAF.ps1' to all Venafi servers.  
The default folder location would be 'C:\Program Files\Venafi\Scripts\AdaptableApp'.

All dependencies on the VenafiPS module have been removed from this version of the driver.

## Usage

### Credentials

| Credential | Required | Credential Type | Credential Placement | Notes |
| --- | --- | --- | --- | --- |
| Imperva API | **YES** | Username | Device or Application Credential | API ID in username<br>API Key in password |
| Venafi API | Optional - Used for:<br>Sub Account Discovery<br>Cert Vault Lookups | Username | Secondary Credential (Application) | Required API Permissions:<br>certificate:manage;configuration:manage;restricted:manage |

### Policy-Level Application Fields
* **Debug Imperva Driver (Yes/No):** Allows you to log debug info for all applications under this policy folder.
* **Discover Sub Accounts (Yes/No):** Enable sub-account discovery. Requires a secondary credential to grant Venafi API access. See below for details.
* **Imperva Base Folder:** Required for sub-account discovery. Example: \VED\Policy\Cloud\Imperva
* **Imperva Discovered Folder:** Folder to place newly discovered sub-accounts (under the Base Folder). Defaults to 'Discovered' if not specified.

### Setup Option 1: Very Manual (No Discovery - Define Individual Applications)
* Create a placeholder device
  * Name the device (for example: Imperva)
  * Set the Hostname/Address to an asterisk '*'
* Create an adaptable application under the Imperva device
  * Set the application name to the Imperva site name
  * Set the application credential to the Imperva API credential
  * Optionally provide a Venafi API credential as the secondary credential
  * Set the PowerShell Script to 'Imperva Cloud WAF'
  * Set Imperva Site ID to the ID number as seen in Imperva
  * You can get debug logs by setting either or both of the following:
    * Set 'Debug Imperva Driver' to 'Yes'
    * Select the checkbox for 'Enable Debug Logging'
* Do not setup any discovery jobs
  * New sites are defined manually

### Setup Option 2: Flat Model (Single Device - Ignore Sub-Accounts)
* Create a new policy folder
  * Name the policy (for example: Imperva)
  * Select the policy's Applications tab and Adaptable sub-tab
    * Set and lock the application credential to the Imperva API credential
      * **NOTE:** The API credential must have authority over all sub-accounts!
    * Optionally set and lock the secondary credential to the Venafi API credential
    * Set and lock the PowerShell Script to 'Imperva Cloud WAF'
    * Set and lock 'Discover Sub Accounts' to No
    * You can enable debug logging for all applications by setting 'Debug Imperva Driver' to 'Yes' at the policy level
* Create a single device under your new policy
  * Name the device (for example: Imperva)
  * Set the Hostname/Address to an asterisk '*'
* Create a new 'Onboard Discovery' job
  * Name the job (for example: Imperva - Flat Discovery)
  * Set 'Installation Type' to 'Adaptable'
  * Optionally select the checkbox for 'Enable Debug Logging'
  * Click [Next]
  * Under 'Devices to Scan', select the new Imperva device
  * Click [Next]
  * Set Placement Rules as desired then click [Next]
  * Set Run Time as desired then click [Create Job]
  * Run your new discovery job to populate applications under a single device
    * This discovery configuration effectively ignores sub-accounts

### Setup Option 3: Simple Sub-Account Model (Sub-Account Devices in One Folder)
* Create a new policy folder
  * Name the policy (for example: Imperva)
  * Select the policy's Applications tab and Adaptable sub-tab
    * Set and lock the application credential to the Imperva API credential
      * **NOTE:** The API credential must have authority over all sub-accounts!
    * Optionally set and lock the secondary credential to the Venafi API credential
    * Set and lock the PowerShell Script to 'Imperva Cloud WAF'
    * Set and lock 'Imperva Base Folder' to the new policy folder
      * For Example: \VED\Policy\Cloud Services\Imperva
    * Set and lock 'Imperva Discovered Folder' to a single dot/period '.'
    * Set and lock 'Discover Sub Accounts' to 'Yes'
    * You can enable debug logging for all applications by setting 'Debug Imperva Driver' to 'Yes' at this policy level
* Create the top-level/parent device under your new policy
  * Name the device (for example: Imperva Main)
  * Set the Hostname/Address to your top-level Account ID (for example: 123456)
* Create a new 'Onboard Discovery' job
  * Name the job (for example: Imperva - Simple Discovery)
  * Set 'Installation Type' to 'Adaptable'
  * Optionally select the checkbox for 'Enable Debug Logging'
  * Click [Next]
  * Under 'Scan all Devices located in this folder', select the new Imperva policy
  * Click [Next]
  * Set Placement Rules as desired then click [Next]
  * Set Run Time as desired then click [Create Job]
  * Run your new discovery job to populate applications under the parent device and discover sub-accounts
    * Devices for new sub-accounts will be created in the base policy folder
    * New sub-accounts will not have any discovered applications until the NEXT discovery job runs
    * All sub-accounts are automatically managed in this configuration
    * Sub-account devices can be renamed as desired, but do not modify the Hostname/Address
    * Sub-policies can be created and devices moved into them, but do not move the devices outside of the base policy
      * This allows you to set different permissions for sub-accounts, if desired

### Setup Option 4: Complex Sub-Account Models (Sub-Account Devices in Multiple Nested Folders with 2 Discovery Jobs)
* Create a new policy folder
  * Name the policy (for example: Imperva)
  * Select the policy's Applications tab and Adaptable sub-tab
    * Set and lock the application credential to the Imperva API credential
      * **NOTE:** The API credential must have authority over all sub-accounts!
    * Optionally set and lock the secondary credential to the Venafi API credential
    * Set and lock the PowerShell Script to 'Imperva Cloud WAF'
    * Set but do not lock 'Discover Sub Accounts' to 'No'
* Create 2-4 sub-policy folders
  * Optionally create a policy for new sub-accounts (for example: Discovered)
  * Optionally create a policy for unmanaged sub-accounts (for example: Ignored)
  * Create a policy for managed sub-accounts (for example: Managed)
  * Create a policy for the parent device (for example: Parent)
    * Set and lock 'Imperva Base Folder' to the new policy folder
      * For Example: \VED\Policy\Cloud Services\Imperva
    * Set and lock 'Imperva Discovered Folder' to one of the following:
      * 'Discovered' if you created a policy for that - These sub-accounts will not be managed in this setup
      * 'Managed' if you want all newly discovered sub-accounts to be immediately managed by default
    * Set and lock 'Discover Sub Accounts' to 'Yes'
    * You can enable debug logging for all applications by setting 'Debug Imperva Driver' to 'Yes' at this policy level
* Create the top-level/parent device under the new 'Parent' folder
  * Name the device (for example: Imperva Main)
  * Set the Hostname/Address to your top-level Account ID (for example: 123456)
* Create a new 'Onboard Discovery' job
  * Name the job (for example: Imperva - Parent Discovery)
  * Set 'Installation Type' to 'Adaptable'
  * Optionally select the checkbox for 'Enable Debug Logging'
  * Click [Next]
  * Under 'Devices to Scan', select the new Imperva parent device (in this example: Imperva Main)
  * Click [Next]
  * Set Placement Rules as desired then click [Next]
  * Set Run Time as desired then click [Create Job]
  * Run your new discovery job to populate applications under the parent device and discover sub-accounts
    * Devices for new sub-accounts will be created in the 'Imperva Discovered Folder' set above
    * New sub-accounts will not have any discovered applications until the NEXT discovery job runs
    * If you specified separate 'Managed' and 'Discovered' folders then newly discovered sub-accounts will not be managed unless moved to the 'Managed' policy folder
    * If you created an 'Ignored' policy folder you can move sub-accounts there to stop further discovery
      * **NOTE:** Already discovered applications will still be managed, but no further discovery will happen in this example configuration. Delete the applications if you want nothing under the new sub-account to be managed.
    * Sub-account devices can be renamed as desired, but do not modify the Hostname/Address
    * Sub-policies can be created under the 'Managed' policy folder and devices moved into them, but do not move the devices outside of the base policy
      * This allows you to set different permissions for sub-accounts, if desired
* Create a second 'Onboard Discovery' job for sub-accounts
  * Name the job (for example: Imperva - Sub-Accounts)
  * Set 'Installation Type' to 'Adaptable'
  * Optionally select the checkbox for 'Enable Debug Logging'
  * Click [Next]
  * Under 'Scan all Devices located in this folder', select the 'Managed' policy folder
  * Click [Next]
  * Set Placement Rules as desired then click [Next]
  * Set Run Time as desired then click [Create Job]
  * Run your new discovery job to populate applications under the managed sub-accounts
* **NOTES**
  * This is a more complex setup with many options not limited to the example shown
  * If you create a separate 'Discovered' folder then you need to periodically review this folder and complete sub-account setup by moving them to 'Managed' or 'Ignored' as desired. In this example, all newly discovered sub-accounts are effectively unmanaged until you take action on them.
  * If you create new sub-accounts directly in the 'Managed' folder and then want to unmanage it, the existing applications will not be automatically unmanaged by Venafi. You will have to take action to remove or disable applications under sub-accounts you no longer wish to manage. Placing new sub-accounts directly into the 'Managed' folder puts the discovery of Imperva into 'Fully Automated' mode essentially.

## Discovery Caveats
If your Imperva API account does not have authority over all sub-accounts you cannot discover new sub-accounts. You can create separate devices using separate Imperva API keys if you wish. Note that you should not use the hostname/address '*' in a scenario like this if you want to generate debug logs as they will collide without an actual account ID. It is recommended to use the actual account ID for all sub-accounts if you are using separate Imperva API keys or do not enable debug on multiple devices at once.

You can just not enable 'Discover Sub Accounts' if you prefer to manually create sub-account devices to be managed instead of using a more complex setup like option 4.

## Support
Please report issues through github. This driver is still being actively supported. This is published on my personal github instance.

## Roadmap
* Handling some of Imperva's flakey API errors could still be improved.
* Tag removed sites as 'obsolete' and disable during discovery.
* Optionally allow removed sites to be automatically deleted by the driver.
* Tag removed sub-accounts as 'obsolete' and disable during sub-account discovery.
* Optionally allow removed sub-accounts to be automatically deleted by the driver.

## Contributing
Assistance is always welcome. I'm not really a programmer. I just play one on community forums.

## Authors and acknowledgment
Mostly me for the moment. Buyer Beware.

Shout outs to my team for their assistance with this driver.
* Thanks to Ticiana for troubleshooting issues with Imperva's v2 API and discovering old private key encryption methods were not being accepted by Imperva.
