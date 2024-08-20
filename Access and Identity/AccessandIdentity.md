**`TLP:CLEAR`**

# Access and Identity Metrics

## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The following are key terms and descriptions used in this document.

**Sensitive Accounts**: This term denotes a set of user accounts that have
access to sensitive and high-value information. As a result, these accounts
may be at a higher risk of being targeted.

### Policies
## 1. MFA Deployment

### Policy
MFA MUST be deployed for all user accounts
- _Rationale:_ Deploying multifactor authentication (MFA) for Microsoft 365 is essential for enhancing security by adding an extra layer of protection, making it significantly harder for unauthorized users to gain access even if passwords are compromised. It helps protect against credential theft, reduces the risk of data breaches, and ensures compliance with industry regulations. Additionally, Microsoft 365 offers flexible and user-friendly options for implementing MFA, such as Conditional Access policies and security defaults, making it adaptable to various organizational needs.

### Implementation

### Instructions
- [Enable Azure MFA](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa)


## 2. Are Legacy Authentication methods blocked?

This section provides policies that reduce security risks related to legacy authentication protocols that do not support multifactor authentication (MFA).

### Policy
Legacy authentication SHALL be blocked.

- _Rationale:_ The security risk of allowing legacy authentication protocols is they do not support MFA. Blocking legacy protocols reduces the impact of user credential theft.


### Resources

- [Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)

- [Five steps to securing your identity infrastructure](https://learn.microsoft.com/en-us/azure/security/fundamentals/steps-secure-identity)


### Implementation

#### Instructions

- [Determine if an agency’s existing applications use legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication#identify-legacy-authentication-use) before blocking legacy authentication across the entire application base.

- Create a [Conditional Access policy to block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy).

  


## 3. Are allowed MFA methods considered to be "Phishing-resistant"
### Policy
The phishing-resistant methods **Azure AD Certificate-Based Authentication (CBA)**, **FIDO2 Security Key** and **Windows Hello for Business** are the recommended authentication options since they offer forms of MFA with the least weaknesses. For federal agencies, Azure AD CBA supports federal PIV card authentication directly to Azure AD.

Policy: Implementation #1 
If on-premises PIV authentication and federation to Azure AD is used, [enforce PIV logon via AD group policy](https://www.idmanagement.gov/implement/scl-windows/).
- _Rationale:_ Weaker forms of MFA do not protect against sophisticated phishing attacks. By enforcing methods resistant to phishing, those risks are minimized.

Policy: Implementation #2 
If phishing-resistant MFA has not been enforced, an alternative MFA method SHALL be enforced for all users.
- _Rationale:_ This is a stopgap security policy to help protect the tenant if phishing-resistant MFA has not been enforced. This policy requires MFA enforcement, thus reducing single-form authentication risk.
- _Note:_ If a conditional access policy has been created enforcing phishing-resistant MFA, then this policy is not necessary. This policy does not dictate the specific MFA method.

Policy: Implementation #3
If phishing-resistant MFA has not been enforced and Microsoft Authenticator is enabled, it SHALL be configured to show login context information.
- _Rationale:_ This stopgap security policy helps protect the tenant when phishing-resistant MFA has not been enforced and Microsoft Authenticator is used. This policy helps improve the security of Microsoft Authenticator by showing user context information, which helps reduce MFA phishing compromises.

Policy: Implementation #4
The Authentication Methods Manage Migration feature SHALL be set to Migration Complete.
- _Rationale:_ To disable the legacy authentication methods screen for the tenant, configure the Manage Migration feature to Migration Complete. The MFA and Self-Service Password Reset (SSPR) authentication methods are both managed from a central admin page, thereby reducing administrative complexity and potential security misconfigurations.

Policy: Implementation #5
The authentication methods SMS, Voice Call, and Email One-Time Passcode (OTP) SHALL be disabled.
- _Rationale:_ SMS, voice call, and email OTP are the weakest authenticators. This policy forces users to use stronger MFA methods.
- _Note:_ This policy is only applicable if the tenant has their Manage Migration feature set to Migration Complete.

Policy: Implementation #6
Phishing-resistant MFA SHALL be required for highly privileged roles.
- _Rationale:_ This is a backup security policy to help protect privileged access to the tenant if the conditional access policy, which requires MFA for all users, is disabled or misconfigured.
- _Note:_ Refer to the Highly Privileged Roles section at the top of this document for a reference list of roles considered highly privileged.

Policy: Implementation #7
Managed devices SHOULD be required for authentication.
- _Rationale:_ The security risk of an adversary authenticating to the tenant from their own device is reduced by requiring a managed device to authenticate. Managed devices are under the provisioning and control of the agency. [OMB-22-09](https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf) states, "When authorizing users to access resources, agencies must consider at least one device-level signal alongside identity information about the authenticated user."

Policy: Implementation #8
Managed Devices SHOULD be required to register MFA.
- _Rationale:_ Reduce risk of an adversary using stolen user credentials and then registering their own MFA device to access the tenant by requiring a managed device provisioned and controlled by the agency to perform registration actions. This prevents the adversary from using their own unmanaged device to perform the registration.

### Resources

- [What authentication and verification methods are available in Microsoft Entra ID?](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods)

- [How to use additional context in Microsoft Authenticator notifications - Authentication methods policy](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-additional-context#enable-additional-context-in-the-portal)

- [M-22-09 Federal Zero Trust Architecture Strategy](https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf)

- [Configure Microsoft Entra hybrid join](https://learn.microsoft.com/en-us/entra/identity/devices/how-to-hybrid-join)

- [Microsoft Entra joined devices](https://learn.microsoft.com/en-us/entra/identity/devices/concept-directory-join)

- [Set up automatic enrollment for Windows devices (for Intune)](https://learn.microsoft.com/en-us/mem/intune/enrollment/windows-enroll)

### License Requirements

- Policies related to managed devices require Microsoft Intune.

### Implementation

#### Implementation #1 Instructions

1. Create a conditional access policy enforcing phishing-resistant MFA for all users. Configure the following policy settings in the new conditional access policy, per the values below:

<pre>
  Users > Include > <b>All users</b>

  Target resources > Cloud apps > <b>All cloud apps</b>

  Access controls > Grant > Grant Access > Require authentication strength > <b>Phishing-resistant MFA</b>
</pre>

#### Implementation #2 Instructions

1. If phishing-resistant MFA has not been enforced for all users yet, create a conditional access policy that enforces MFA but does not dictate MFA method. Configure the following policy settings in the new conditional access policy, per the values below:

<pre>
  Users > Include > <b>All users</b>

  Target resources > Cloud apps > <b>All cloud apps</b>

  Access controls > Grant > Grant Access > <b>Require multifactor authentication</b>
</pre>

#### Implementation #3 Instructions
If phishing-resistant MFA has not been deployed yet and Microsoft Authenticator is in use, configure Authenticator to display context information to users when they log in.

1. In **Azure Active Directory**, click **Security > Authentication methods > Microsoft Authenticator**.
2. Click the **Configure** tab.
3. For **Allow use of Microsoft Authenticator OTP** select *No*.
4. Under **Show application name in push and passwordless notifications** select **Status > Enabled** and **Target > Include > All users**.
5. Under **Show geographic location in push and passwordless notifications** select **Status > Enabled** and **Target > Include > All users**.
6. Select **Save**


#### Implementation #4 Instructions
1. Go through the process of [migrating from the legacy Azure AD MFA and Self-Service Password Reset (SSPR) administration pages to the new unified Authentication Methods policy page](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage).
2. Once ready to finish the migration, [set the **Manage Migration** option to **Migration Complete**](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage#finish-the-migration).

#### Implementation #5 Instructions
1. In **Azure Active Directory**, click **Security > Authentication methods**
2. Click on the **SMS**, **Voice Call**, and **Email OTP** authentication methods and disable each of them. Their statuses should be **Enabled > No** on the **Authentication methods > Policies** page.

#### Implementation #6 Instructions

1. Create a conditional access policy enforcing phishing-resistant MFA for highly privileged roles.  Configure the following policy settings in the new conditional access policy, per the values below:

<pre>
  Users > Include > Select users and groups > Directory roles > <b>select each of the roles listed in the Highly Privileged Roles section at the top of this document</b>

  Target resources > Cloud apps > <b>All cloud apps</b>

  Access controls > Grant > Grant Access > Require authentication strength > <b>Phishing-resistant MFA</b>
</pre>

#### Implementation #7 Instructions

1. Create a conditional access policy requiring a user's device to be either Microsoft Entra hybrid joined or compliant during authentication. Configure the following policy settings in the new conditional access policy, per the values below:

<pre>
  Users > Include > <b>All users</b>

  Target resources > Cloud apps > <b>All cloud apps</b>

  Access controls > Grant > Grant Access > <b>Require device to be marked as compliant</b> and <b>Require Microsoft Entra hybrid joined device</b> > For multiple controls > <b>Require one of the selected controls</b>
</pre>

#### Implementation #8 Instructions

1. Create a conditional access policy requiring a user to be on a managed device when registering for MFA. Configure the following policy settings in the new conditional access policy, per the values below:

<pre>
  Users > Include > <b>All users</b>

  Target resources > User actions > <b>Register security information</b>

  Access controls > Grant > Grant Access > <b>Require device to be marked as compliant</b> and <b>Require Microsoft Entra hybrid joined device</b> > For multiple controls > <b>Require one of the selected controls</b>
</pre>



## 4. Is there an Active Password Policy?
### Policy
An Active Password Policy MUST be configured for Microsoft 365. 

- _Rationale:_ Implementing a robust password policy in Microsoft 365 is vital for maintaining security by ensuring that passwords are strong and diverse, which helps protect against common attacks and limits the damage of successful breaches.

### Implementation
1. Log into the [Microsoft Entra Admin Center Password Policy Settings]([url](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection/fromNav/Identity))
2. Fill the following information
   - Lockout threshold: 10
   - Lockout duration in seconds: 60
   - Enforce Custom List: Yes
   - Custom Banned Password List:  Copy the passwords from:  [SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt at master]([url](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt))
   - Enable Password protection on Windows Server Active Directory: Yes
   - Mode: Enforced

## 5. Can only administrators register and consent to applications?

This section provides policies that help reduce security risk of malicious applications or service principals added to the tenant by non-privileged users. Malicious applications can perform many of the same operations as interactive users and can access data on behalf of compromised users. These policies apply to custom-developed applications and applications published by third-party vendors.

### Policy
#### Implementation #1
Only administrators SHALL be allowed to register applications.
- _Rationale:_ Application access for the tenant presents a heightened security risk compared to interactive user access because applications are typically not subject to critical security protections, such as MFA policies. Reduce risk of unauthorized users installing malicious applications into the tenant by ensuring that only specific privileged users can register applications.
- _Last modified:_ June 2023

#### Implementation #2
Only administrators SHALL be allowed to consent to applications.
- _Rationale:_ Limiting applications consent to only specific privileged users reduces risk of users giving insecure applications access to their data via [consent grant attacks](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide).
- _Last modified:_ June 2023

#### Implementation #3
An admin consent workflow SHALL be configured for applications.
- _Rationale:_ Configuring an admin consent workflow reduces the risk of the previous policy by setting up a process for users to securely request access to applications necessary for business purposes. Administrators have the opportunity to review the permissions requested by new applications and approve or deny access based on a risk assessment.
- _Last modified:_ June 2023

#### Implementation #4
Group owners SHALL NOT be allowed to consent to applications.
- _Rationale:_ In M365, group owners and team owners can consent to applications accessing data in the tenant. By requiring consent requests to go through an approval workflow, risk of exposure to malicious applications is reduced.
- _Last modified:_ June 2023

### Resources

- [Restrict Application Registration for Non-Privileged Users](https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/ActiveDirectory/users-can-register-applications.html)

- [Enforce Administrators to Provide Consent for Apps Before Use](https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/ActiveDirectory/users-can-consent-to-apps-accessing-company-data-on-their-behalf.html)

- [Configure the admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow)

### License Requirements

- N/A

### Implementation

#### Implementation #1 Instructions

1.  In **Azure Active Directory**, under **Manage**, select **Users**.

2. Select **User settings**.

3. For **Users can register applications**, select **No.**

4. Click **Save**.

#### Implementation #2 Instructions

1.  In **Azure Active Directory** under **Manage**, select **Enterprise Applications.**

2. Under **Security**, select **Consent and permissions.** Then select **User Consent Settings.**

3. Under **User consent for applications**, select **Do not allow user consent.**

4. Click **Save**.

#### Implementation #3 Instructions

1.  In **Azure Active Directory** create a new Azure AD Group that contains admin users responsible for reviewing and adjudicating application consent requests. Group members will be notified when users request consent for new applications.

2. Then in **Azure Active Directory** under **Applications**, select **Enterprise Applications.**

3. Under **Security**, select **Consent and permissions**. Then select **Admin consent settings**.

4. Under **Admin consent requests** > **Users can request admin consent to apps they are unable to consent to** select **Yes**.

5. Under **Who can review admin consent requests**, select **+ Add groups** and select the group responsible for reviewing and adjudicating app requests (created in step one above).

6. Click **Save**.

#### Implementation #4 Instructions

1.  In **Azure Active Directory** under **Applications**, select **Enterprise Applications.**

2. Under **Security**, select **Consent and permissions.** Then select **User Consent Settings.**

3. Under **Group owner consent for apps accessing data**, select **Do not allow group owner consent.**

4. Click **Save**.


## 6. Number of Unused Licenses

### Policy
Licenses that are not assigned to any user SHALL be removed from the environment. 

- _Rationale:_ Removing unassigned licenses in Microsoft 365 is important for cost management and ensuring efficient use of resources. By regularly reviewing and removing unassigned licenses, organizations can avoid unnecessary expenses and free up licenses for new users

### Implementation

### Instructions
1. Login to the [Microsoft Admin Center ](admin.microsoft.com) as an administrator
2. On the navigation bar, select Billing dropdown and select Licenses
3. Identify unassigned licenses and remove them, ensuring the organization only pays for the active licenses 


## 7. A custom policy SHALL be configured to protect PII and sensitive information, as defined by the agency. 

### Policy
At a minimum, credit card numbers, U.S. Individual Taxpayer Identification Numbers (ITIN), and U.S. Social Security numbers (SSN) SHALL be blocked.

- _Rationale:_ Users may inadvertently share sensitive information with
               others who should not have access to it. DLP policies
               provide a way for agencies to detect and prevent
               unauthorized disclosures.

#### Part 1
The custom policy SHOULD be applied to Exchange, OneDrive, SharePoint, Teams chat, and Devices.

- _Rationale:_ Unauthorized disclosures may happen through M365 services
               or endpoint devices. DLP policies should cover all
               affected locations to be effective.

  
#### Part 2
The action for the custom policy SHOULD be set to block sharing sensitive information with everyone.

<!--Criticality: SHOULD -->
- _Rationale:_ Access to sensitive information should be prohibited unless
               explicitly allowed. Specific exemptions can be made based
               on agency policies and valid business justifications.


#### Part 3
Notifications to inform users and help educate them on the proper use of sensitive information SHOULD be enabled in the custom policy.

<!--Criticality: SHOULD -->
- _Rationale:_ Some users may not be aware of agency policies on
               proper use of sensitive information. Enabling
               notifications provides positive feedback to users when
               accessing sensitive information.


#### Part 4
A list of apps that are restricted from accessing files protected by DLP policy SHOULD be defined.

<!--Criticality: SHOULD -->
- _Rationale:_ Some apps may inappropriately share accessed files or not
               conform to agency policies for access to sensitive
               information. Defining a list of those apps makes it
               possible to use DLP policies to restrict those apps' access
               to sensitive information on endpoints using Defender.

#### Part 5
The custom policy SHOULD include an action to block access to sensitive
information by restricted apps and unwanted Bluetooth applications.

<!--Criticality: SHOULD -->
- _Rationale:_ Some apps may inappropriately share accessed files
               or not conform to agency policies for access to sensitive
               information. Defining a DLP policy with an action to block
               access from restricted apps and unwanted Bluetooth
               applications prevents unauthorized disclosure by those
               programs.
- _Note:_
  - This action can only be included if at least one device is onboarded
    to the agency tenant. Otherwise, the option to block restricted apps will
    not be available.

### Resources

- [Plan for data loss prevention (DLP) \| Microsoft
  Learn](https://learn.microsoft.com/en-us/purview/dlp-overview-plan-for-dlp?view=o365-worldwide)

- [Data loss prevention in Exchange Online \| Microsoft
  Learn](https://learn.microsoft.com/en-us/exchange/security-and-compliance/data-loss-prevention/data-loss-prevention)

- [Personally identifiable information (PII) \|
  NIST](https://csrc.nist.gov/glossary/term/personally_identifiable_information#:~:text=NISTIR%208259,2%20under%20PII%20from%20EGovAct)

- [Sensitive information \|
  NIST](https://csrc.nist.gov/glossary/term/sensitive_information)

- [Get started with Endpoint data loss prevention - Microsoft Purview
  (compliance) \| Microsoft Learn](https://learn.microsoft.com/en-us/purview/endpoint-dlp-getting-started?view=o365-worldwide)

### License Requirements

- DLP for Teams requires an E5 or G5 license. See [Microsoft Purview Data Loss Prevention: Data Loss Prevention for Teams \| Microsoft
  Learn](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-365-security-compliance-licensing-guidance#microsoft-purview-data-loss-prevention-data-loss-prevention-dlp-for-teams)
  for more information.

- DLP for Endpoint requires an E5 or G5 license. See [Get started with
  Endpoint data loss prevention - Microsoft Purview (compliance) \|
  Microsoft
  Learn](https://learn.microsoft.com/en-us/purview/endpoint-dlp-getting-started?view=o365-worldwide)
  for more information.

### Implementation

#### Part 1 Instructions

1. Sign in to the **Microsoft Purview compliance portal**.

2. Under the **Solutions** section on the left-hand menu, select **Data loss
   prevention**.

3. Select **Policies** from the top of the page.

4. Select **Create policy**.

5. From the **Categories** list, select **Custom**.

6. From the **Templates** list, select **Custom policy** and then click
   **Next**.

7. Edit the name and description of the policy if desired, then click
   **Next**.

8. Under **Choose locations to apply the policy**, set **Status** to **On**
   for at least the Exchange email, OneDrive accounts, SharePoint
   sites, Teams chat and channel messages, and Devices locations, then
   click **Next**.

9. Under **Define policy settings**, select **Create or customize advanced
   DLP rules**, and then click **Next**.

10. Click **Create rule**. Assign the rule an appropriate name and
   description.

11. Click **Add condition**, then **Content contains**.

12. Click **Add**, then **Sensitive info types**.

13. Add information types that protect information sensitive to the agency.
    At a minimum, the agency should protect:

    - Credit card numbers
    - U.S. Individual Taxpayer Identification Numbers (ITIN)
    - U.S. Social Security Numbers (SSN)
    - All agency-defined PII and sensitive information

14. Click **Add**.

15. Under **Actions**, click **Add an action**.

16. Check **Restrict Access or encrypt the content in Microsoft 365
    locations**.

17. Under this action, select **Block Everyone**.

18. Under **User notifications**, turn on **Use notifications to inform your users and help educate them on the proper use of sensitive info**.

19. Under **Microsoft 365 services**, a section that appears after user notifications are turned on, check the box next to **Notify users in Office 365 service with a policy tip**.

20. Click **Save**, then **Next**.

21. Select **Turn it on right away**, then click **Next**.

22. Click **Submit**.

#### Part 2 Instructions

See Implementation #1 Instructions step 8
   for details on enforcing DLP policy in specific M365 service locations.

#### Part 3 Instructions

See Implementation #1 Instructions steps
   15-17 for details on configuring DLP policy to block sharing sensitive
   information with everyone.

#### Part 4 Instructions

See Implementation #1 Instructions steps
   18-19 for details on configuring DLP policy to notify users when accessing
   sensitive information.

#### Part 5 Instructions

1. Sign in to the **Microsoft Purview compliance portal**.

2. Under **Solutions**, select **Data loss prevention**.

3. Go to **Endpoint DLP Settings**.

4. Go to **Restricted apps and app groups**.

5. Click **Add or edit Restricted Apps**.

6. Enter an app and executable name to disallow said app from
   accessing protected files, and log the incident.

7. Return and click **Unallowed Bluetooth apps**.

8. Click **Add or edit unallowed Bluetooth apps**.

9. Enter an app and executable name to disallow said app from
   accessing protected files, and log the incident.

#### Instructions

If restricted app and unwanted Bluetooth app restrictions are desired,
associated devices must be onboarded with Defender for Endpoint
before the instructions below can be completed.

1. Sign in to the **Microsoft Purview compliance portal**.

2. Under **Solutions**, select **Data loss prevention**.

3. Select **Policies** from the top of the page.

4. Find the custom DLP policy configured under
   Implementation #1 Instructions] in the list
   and click the Policy name to select.

5. Select **Edit Policy**.

6. Click **Next** on each page in the policy wizard until you reach the
   Advanced DLP rules page.

7. Select the relevant rule and click the pencil icon to edit it.

8. Under **Actions**, click **Add an action**.

9. Choose **Audit or restrict activities on device**

10. Under **File activities for all apps**, select
    **Apply restrictions to specific activity**.

11. Check the box next to **Copy or move using unallowed Bluetooth app**
    and set its action to **Block**.

12. Under **Restricted app activities**, check the **Access by restricted apps** box
   and set the action drop-down to **Block**.

13. Click **Save** to save the changes.

14. Click **Next** on each page until reaching the
    **Review your policy and create it** page.

15. Review the policy and click **Submit** to complete the policy changes.


**`TLP:CLEAR`**
