**KQL rule making**



**Password spray** - Attacker tries one common password against many accounts to avoid lockout thresholds.

&#x09;

&#x09;KQL Query -

**Signinlogs**

**| where TimeGenerated > ago(1h)**

**| where ResultType != 0**

**| summarize**

&#x09;**AttemptCount = count()**

&#x09;**TargetAccount = dcount(UserPrincipalName)**

&#x09;**AccountList = make\_set(UserPrincipalName)**

&#x09;**by IPAddress**

**| where TargetAccount >= 5**

**| extend Severity = case(**

&#x20;   **TargetAccounts >= 20, "High",**

&#x20;   **TargetAccounts >= 10, "Medium",**

&#x20;   **"Low")**

**| project IPAddress, AttemptCount, TargetAccounts,**

&#x20;   **AccountList, FirstAttempt, LastAttempt, Severity**

**| sort by TargetAccounts desc**



False positive - legitimate user testing



**Impossible Travel Login** - It means someone logs in from two different geographic locations in a time window that is physically impossible to travel between.



&#x09;KQL Query -

**SigninLogs**

**| where TimeGenerated > ago(24h)**

**| where ResultType == 0**

**| where isnotempty(Location)**

**| project TimeGenerated, UserPrincipalName,**

&#x20;   **IPAddress, Location,**

&#x20;   **City = tostring(LocationDetails.city),**

&#x20;   **Country = tostring(LocationDetails.countryOrRegion)**

**| sort by UserPrincipalName asc, TimeGenerated asc**

**| extend PreviousCountry = prev(Country, 1),**

&#x20;   **PreviousTime = prev(TimeGenerated, 1),**

&#x20;   **PreviousUser = prev(UserPrincipalName, 1)**

**| where UserPrincipalName == PreviousUser**

**| where Country != PreviousCountry**

**| extend TimeDiffMinutes = datetime\_diff('minute', TimeGenerated, PreviousTime)**

**| where TimeDiffMinutes <= 200**

**| project**

&#x20;   **UserPrincipalName,**

&#x20;   **CurrentCountry = Country,**

&#x20;   **CurrentCity = City,**

&#x20;   **CurrentIP = IPAddress,**

&#x20;   **CurrentLoginTime = TimeGenerated,**

&#x20;   **PreviousCountry,**

&#x20;   **PreviousLoginTime = PreviousTime,**

&#x20;   **TimeDifferenceMinutes = TimeDiffMinutes**

**| sort by TimeDifferenceMinutes asc**



False positive - VPN, real travel



**New Privileged Account Creation** - When an attacker gets into a system one of the first things they do is create a backdoor. The most common way is creating a new account and giving it admin or privileged role access.



&#x09;KQL -



**let NewUsers = AuditLogs**

**| where TimeGenerated > ago(24h)**

**| where OperationName == "Add user"**

**| where Result == "success"**

**| project**

&#x20;   **UserCreatedTime = TimeGenerated,**

&#x20;   **NewUser = tostring(TargetResources\[0].userPrincipalName),**

&#x20;   **CreatedBy = tostring(InitiatedBy.user.userPrincipalName);**

**let RoleAssignments = AuditLogs**

**| where TimeGenerated > ago(24h)**

**| where OperationName == "Add member to role"**

**| where Result == "success"**

**| project**

&#x20;   **RoleAssignedTime = TimeGenerated,**

&#x20;   **AssignedUser = tostring(TargetResources\[0].userPrincipalName),**

&#x20;   **RoleName = tostring(TargetResources\[1].displayName),**

&#x20;   **AssignedBy = tostring(InitiatedBy.user.userPrincipalName);**

**NewUsers**

**| join kind=inner RoleAssignments on $left.NewUser == $right.AssignedUser**



**Malicious IP Sign-in** -  successful login from an IP address that is known to be malicious — meaning it appears on threat intelligence feeds as associated with:



Known attackers

Tor exit nodes

Botnets

Command and control servers

VPN services used by attackers

Brute force attack sources



&#x09;KQL -



**let MaliciousIPs = ThreatIntelligenceIndicator**

**| where TimeGenerated > ago(7d)**

**| where isnotempty(NetworkIP)**

**| where ExpirationDateTime > now()**

**| where ConfidenceScore >= 50**

**| project MaliciousIP = NetworkIP, ThreatType,**

&#x20;   **ConfidenceScore, Description;**

**let RecentLogins = SigninLogs**

**| where TimeGenerated > ago(24h)**

**| where ResultType == 0**

**| project**

&#x20;   **LoginTime = TimeGenerated,**

&#x20;   **UserPrincipalName,**

&#x20;   **LoginIP = IPAddress,**

&#x20;   **Location,**

&#x20;   **AppDisplayName;**

**RecentLogins**

**| join kind=inner MaliciousIPs on $left.LoginIP == $right.MaliciousIP**



**Bulk File Download from SharePoint** - A user downloading an unusually large number of files from SharePoint in a short period of time. This is called Data Exfiltration — an attacker or malicious insider stealing company data before:

Getting caught

Leaving the company

Selling data to competitors

Ransomware preparation



&#x09;KQL -



**OfficeActivity**

**| where TimeGenerated > ago(1h)**

**| where OfficeWorkload == "SharePoint"**

**| where Operation in ("FileDownloaded",**

&#x20;   **"FileSyncDownloadedFull", "FileAccessed")**

**| summarize**

&#x20;   **DownloadCount = count(),**

&#x20;   **UniqueFiles = dcount(ObjectId),**

&#x20;   **SiteList = make\_set(SiteUrl),**

&#x20;   **FirstDownload = min(TimeGenerated),**

&#x20;   **LastDownload = max(TimeGenerated)**

&#x20;   **by UserId, ClientIP**

**| where DownloadCount >= 50**

**| project**

&#x20;   **UserId,**

&#x20;   **ClientIP,**

&#x20;   **DownloadCount,**

&#x20;   **UniqueFiles,**

&#x20;   **DurationMinutes,**

&#x20;   **DownloadsPerMinute,**

&#x20;   **FirstDownload,**

&#x20;   **LastDownload,**

&#x20;   **SiteList,**

&#x20;   **Severity**

**| sort by DownloadCount desc**



**MFA Disabled for a User** - Someone disabling Multi-Factor Authentication for a user account. MFA is one of the strongest defenses against account takeover. When an attacker gains admin access one of the first things they do is disable MFA for accounts they control so they can log in freely without needing the second factor.



&#x09;KQL -



**let DirectMFADisable = AuditLogs**

**| where TimeGenerated > ago(24h)**

**| where OperationName == "Disable Strong Authentication"**

**| where Result == "success"**

**| project**

&#x20;   **TimeGenerated,**

&#x20;   **TargetUser = tostring(TargetResources\[0].userPrincipalName),**

&#x20;   **DisabledBy = tostring(InitiatedBy.user.userPrincipalName),**

&#x20;   **DisabledByIP = tostring(InitiatedBy.user.ipAddress),**

&#x20;   **Method = "Direct MFA Disable";**

**let UserUpdateMFADisable = AuditLogs**

**| where TimeGenerated > ago(24h)**

**| where OperationName == "Update user"**

**| where Result == "success"**

**| mv-expand ModifiedProperties = TargetResources\[0].modifiedProperties**

**| where ModifiedProperties.displayName == "StrongAuthenticationRequirement"**

**| where tostring(ModifiedProperties.newValue) == "\[]"**

**| project**

&#x20;   **TimeGenerated,**

&#x20;   **TargetUser = tostring(TargetResources\[0].userPrincipalName),**

&#x20;   **DisabledBy = tostring(InitiatedBy.user.userPrincipalName),**

&#x20;   **DisabledByIP = tostring(InitiatedBy.user.ipAddress),**

&#x20;   **Method = "User Property Update";**

**union DirectMFADisable, UserUpdateMFADisable**



**Mass Email Forwarding Rule Created** - A user creating an automatic email forwarding rule that sends all incoming emails to an external address without the user's knowledge or interaction.



&#x09;KQL -



**OfficeActivity**

**| where TimeGenerated > ago(24h)**

**| where Operation in ("New-InboxRule", "Set-InboxRule")**

**| mv-expand Parameters**

**| extend ParameterName = tostring(Parameters.Name)**

**| extend ParameterValue = tostring(Parameters.Value)**

**| where ParameterName in (**

&#x20;   **"ForwardTo",**

&#x20;   **"ForwardAsAttachmentTo",**

&#x20;   **"RedirectTo")**

**| extend IsExternal = ParameterValue !contains**

&#x20;   **"yourdomain.com"**



**Unusual Azure Resource Deletion** - Multiple Azure resources being deleted in a short time window. This covers two very different but equally dangerous scenarios — attacker covering tracks or a destructive attack designed to cause maximum damage.



&#x09;KQL -



**AzureActivity**

**| where TimeGenerated > ago(1h)**

**| where OperationNameValue has "DELETE"**

**| where ActivityStatusValue == "Success"**

**| where OperationNameValue !has**

&#x20;   **"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES"**

**| where OperationNameValue !has**

&#x20;   **"MICROSOFT.INSIGHTS/ACTIVITYLOGALERTS"**

**| summarize**

&#x20;   **DeletionCount = count(),**

&#x20;   **ResourcesDeleted = make\_set(Resource),**

&#x20;   **ResourceTypes = make\_set(OperationNameValue),**

&#x20;   **FirstDeletion = min(TimeGenerated),**

&#x20;   **LastDeletion = max(TimeGenerated),**

&#x20;   **ResourceGroupsAffected = dcount(ResourceGroup)**

&#x20;   **by Caller, SubscriptionId**



**Privilege Access Granted -**Monitored baseline tracking capturing new user access mapping across key infrastructure components.



Potential False Positives: Direct resource allocation matching normal admin onboarding tickets.



&#x09;KQL -



**AuditLogs**

**| where ActivityDisplayName contains "Add owner"**

**| extend**

&#x20;    **timestamp = TimeGenerated,**

&#x20;    **AccessGrantedBy = tostring(InitiatedBy.user.userPrincipalName),**

&#x20;    **AccessGrantedByDisplayName = tostring(InitiatedBy.user.displayName),**

&#x20;    **AccessAssignedTo = tostring(TargetResources\[0].userPrincipalName),**

&#x20;    **AccessAssignedDisplayName =**

**tostring(TargetResources\[0].displayName),**

&#x20;    **Role = tostring(TargetResources\[0].modifiedProperties\[0].newValue),**

&#x20;    **ResourceName =**

**tostring(TargetResources\[0].modifiedProperties\[1].newValue),**

&#x20;    **ResourceType = tostring(TargetResources\[1].type)**

**| where AccessGrantedBy != AccessAssignedTo  // Ensuring the grantor and**

**assignee are different**

**| project**

&#x20;    **timestamp,**

&#x20;    **AccessGrantedBy,**

&#x20;    **AccessAssignedTo,**

&#x20;    **Role,**

&#x20;    **ActivityDisplayName,**

&#x20;    **ResourceName,**

&#x20;    **ResourceType**

**| extend Severity = "Medium"**



**HTTP Unauthorized Brute Force Attack(40031)** - Monitors standardized perimeter syslog feeds mapping ongoing web authentication loops dropping unauthorized responses.



Potential False Positives: Internal connectivity testing monitors or aggressive vulnerability scanners operating natively.



&#x09;KQL -



**CommonSecurityLog**

**| where LogSeverity contains "4"**

**| where not (**

&#x20;            **DeviceEventClassID == "SSH User Authentication Brute Force**

**Attempt(40015)"**

&#x20;        **)**

**| summarize**

&#x20;    **by**

&#x20;    **TimeGenerated,**

&#x20;    **DeviceVersion,**

&#x20;    **DeviceEventClassID,**

&#x20;    **SourceUserName,**

&#x20;    **SourceIP,**

&#x20;    **SourcePort,**

&#x20;    **DestinationIP,**

&#x20;    **DestinationPort,**

&#x20;    **RequestURL,**

&#x20;    **DeviceAction,**

&#x20;    **ApplicationProtocol,**

&#x20;    **EventCount**



**Changes to Network Security Groups (NSGs) made from outside the office -** Immediately tracks firewall policy alterations targeting active cloud structures executing outside standard trusted corporate egress spaces.



Potential False Positives: Authorized on-call administrators modifying parameters from home networks or field terminals.



**AzureActivity**

**| where OperationNameValue contains**

**"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE" or**

**OperationNameValue contains**

**"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/Delete"**

**| extend timestamp = TimeGenerated, Resource = ResourceId, Status =**

**ActivityStatus**

**| summarize count= count() by OperationNameValue, Caller,**

**CallerIpAddress, CategoryValue, ResourceGroup**



**Apache HTTP Server Reverse Proxy Security Bypass Vulnerability(34485) -** Identifies indicators matching reverse proxy web exploitation behavior payloads while skipping out established expected validation domains.



Potential False Positives: Third-party vendor platforms utilizing overlapping, unconventional API tracking strings.



**CommonSecurityLog**

**| where LogSeverity == "3"**

**| where not(DeviceEventClassID has\_any (excludeDomains))**

**| summarize**

&#x20;    **by**

&#x20;    **TimeGenerated,**

&#x20;    **DeviceVersion,**

&#x20;    **DeviceEventClassID,**

&#x20;    **SourceUserName,**

&#x20;    **SourceIP,**

&#x20;    **SourcePort,**

&#x20;    **DestinationIP,**

&#x20;    **DestinationPort,**

&#x20;    **RequestURL,**

&#x20;    **AdditionalExtensions,**

&#x20;    **DeviceAction,**

&#x20;    **ApplicationProtocol,**

&#x20;    **EventCount**

