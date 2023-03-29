# Imperva Cloud WAF
Adaptable Application driver for Imperva's cloud-based WAF (https://my.imperva.com) that makes full use of current Imperva APIs.

## Description
This adaptable application uses Imperva's API to gather site details and perform validation of custom certificates on the platform. Discovery requires that Venafi connect directly to the website port as there is no way to retrieve the public certificate via the API. Validation of legacy websites may also require direct connection (used as a fallback for when the API doesn't provide this information).

For Enterprise customers, sub-accounts can either be under a single consolidated "Imperva" device or separately with a device linked to each sub-account. Multiple API keys are not required to manage sub-accounts separately, but this is an option if your environment requires/prefers it as well.

## Installation
Upload the adaptable log driver file 'Imperva Cloud WAF.ps1' to all Venafi servers.
The default folder location would be 'C:\Program Files\Venafi\Scripts\AdaptableApp'.

## Usage

### Credentials
You will pass the API credentials to the driver as a 'Username Credential' and linked either as the 'Device Credential' or the 'Application Credential'. Use the API ID as the username and the API Key as the password.

### Policy-Level Application Fields
Debug Imperva Cloud WAF Driver (Yes/No) - Allows you to log debug info for all applications under this policy folder.

### Device Option 1: No Discovery - Define individual applications
Create a new adaptable application. Select the 'Imperva Cloud WAF' as the PowerShell script. Set 'Imperva Site ID' (mandatory field).
At this level, setting 'Debug Imperva Cloud WAF Driver' and 'Enable Debug Logging' function identically and will trigger log creation for this application.

### Device Option 2: API ID based restrictions
Create a placeholder device named, for example, 'Imperva Cloud WAF'. Leave the hostname blank. Attach the appropriately scoped API credential to the device as the 'Device Credential' and then run a discovery job against this device. All sites visible to this API ID will be discovered and created as applications underneath the placeholder object.

In this configuration model, all sites visible to the API credential will be placed under the placeholder device. Sub-accounts are effectively ignored.

### Device Option 3: Sub-Account based devices
Create a placeholder device named, for example, 'Imperva: Frisbee Division', and set the 'Hostname/Address' to the sub-account ID to link to this device such as '12345678'. Attach an API credential that can manipulate at least this sub-account to the device as the 'Device Credential' and then run a discovery job against this device. All sites in this sub-account will be discovered and created as applications underneath the placeholder object. Sites not linked to this sub-account will be ignored by discovery.

This configuration option permits you to organize different sub-accounts and assign permissions accordingly. Organization tends to be better, by default. It is more versatile, but you will have to be sure to add new sub-accounts as new devices if you want them to be managed by Venafi.

## Support
Please report issues through github. This driver is still being actively supported. This may or may not end up published on Venafi's gitlab instance.

## Roadmap
Functionally this is mostly 'complete' but handling some of Imperva's flakey API errors could be improved.

## Contributing
Assistance is always welcome. I'm not really a programmer. I just play one on community forums.

## Authors and acknowledgment
Just me for the moment. Buyer Beware.
