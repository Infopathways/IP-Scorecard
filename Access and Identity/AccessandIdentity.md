**`TLP:CLEAR`**

# Access and Identity Metrics



## Key Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

The following are key terms and descriptions used in this document.

**Sensitive Accounts**: This term denotes a set of user accounts that have
access to sensitive and high-value information. As a result, these accounts
may be at a higher risk of being targeted.


### Policies
## 1. Legacy Authentication

This section provides policies that reduce security risks related to legacy authentication protocols that do not support multifactor authentication (MFA).

### Policies
#### MS.AAD.1.1v1
Legacy authentication SHALL be blocked.

<!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->
- _Rationale:_ The security risk of allowing legacy authentication protocols is they do not support MFA. Blocking legacy protocols reduces the impact of user credential theft.
- _Last modified:_ June 2023

### Resources

- [Common Conditional Access policy: Block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy)

- [Five steps to securing your identity infrastructure](https://learn.microsoft.com/en-us/azure/security/fundamentals/steps-secure-identity)

### License Requirements

- N/A

### Implementation

#### MS.AAD.1.1v1 Instructions

- [Determine if an agency’s existing applications use legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication#identify-legacy-authentication-use) before blocking legacy authentication across the entire application base.

- Create a [Conditional Access policy to block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy).

## 2. Risk Based Policies

This section provides policies that reduce security risks related to potentially compromised user accounts. These policies combine Azure AD Identity Protection and Azure AD Conditional Access. Azure AD Identity Protection uses numerous signals to detect the risk level for each user or sign-in and determine if an account may have been compromised.

- _Additional mitigations to reduce risks associated with the authentication of workload identities:_ Although not covered in this baseline due to the need for an additional non-standard license, Microsoft provides support for mitigating risks related to workload identities (Azure AD applications or service principals). Agencies should strongly consider implementing this feature because workload identities present many of the same risks as interactive user access and are commonly used in modern systems. CISA urges organizations to [apply Conditional Access policies to workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity).

- _Note:_ In this section, the term ["high risk"](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks) denotes the risk level applied by the Azure AD Identity Protection service to a user account or sign-in event.
#### MS.DEFENDER.1.3v1
All users SHALL be added to Defender for Office 365 protection in either the standard or strict preset security policy.

<!--Policy: MS.DEFENDER.1.3v1; Criticality: SHALL -->
- _Rationale:_ Important user protections are provided by Defender for Office 365 protection, including safe attachments and safe links. By using the preset policies, administrators can help ensure all new and existing users have secure defaults applied automatically.
- _Last modified:_ June 2023
- _Note:_
  - The standard and strict preset security policies must be enabled as directed
    by [MS.DEFENDER.1.1v1](#msdefender11v1) for protections to be applied.
  - Specific user accounts, except for sensitive accounts, MAY be exempt from the preset policies, provided they are added to one or more custom policies offering comparable protection. These users might need flexibility not offered by the preset policies. Their accounts should be added to a custom policy conforming as closely as possible to the settings used by the preset policies. See the **Resources** section for more details on configuring policies.

#### MS.DEFENDER.1.4v1
Sensitive accounts SHALL be added to Exchange Online Protection in the strict preset security policy.

<!--Policy: MS.DEFENDER.1.4v1; Criticality: SHALL -->
- _Rationale:_ Unauthorized access to a sensitive account may result in greater harm than a standard user account. Adding sensitive accounts to the strict preset security policy, with its increased protections, better mitigates their elevated risk to email threats.
- _Last modified:_ June 2023
- _Note:_ The strict preset security policy must be enabled to protect
          sensitive accounts.

#### MS.DEFENDER.1.5v1
Sensitive accounts SHALL be added to Defender for Office 365 protection in the strict preset security policy.

<!--Policy: MS.DEFENDER.1.5v1; Criticality: SHALL -->
- _Rationale:_ Unauthorized access to a sensitive account may result in greater harm than to a standard user account. Adding sensitive accounts to the strict preset security policy, with its increased protections, better mitigates their elevated risk.
- _Last modified:_ June 2023
- _Note:_ The strict preset security policy must be enabled to protect
          sensitive accounts.

### Resources

- [Use the Microsoft 365 Defender portal to assign Standard and Strict preset security policies to users \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#use-the-microsoft-365-defender-portal-to-assign-standard-and-strict-preset-security-policies-to-users)
- [Recommended settings for EOP and Microsoft Defender for Office 365
  security \| Microsoft
  Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365)
- [Configure anti-phishing policies in EOP \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-eop-configure?view=o365-worldwide)
- [Configure anti-malware policies in EOP \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure?view=o365-worldwide)
- [Configure anti-spam policies in EOP \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-policies-configure?view=o365-worldwide)
- [Configure anti-phishing policies in Defender for Office 365 \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-mdo-configure?view=o365-worldwide)
- [Set up Safe Attachments policies in Microsoft Defender for Office 365 \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-policies-configure?view=o365-worldwide)
- [Set up Safe Links policies in Microsoft Defender for Office 365 \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure?view=o365-worldwide)

### License Requirements

- Defender for Office 365 capabilities require Defender for Office 365 Plan 1 or 2. These are included with E5 and G5 and are available as add-ons for E3 and G3.

### Implementation

#### MS.DEFENDER.1.1v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under **Standard protection**, slide the toggle switch to the right so the text next to the toggle reads **Standard protection is on**.
6. Under **Strict protection**, slide the toggle switch to the right so the text next to the toggle reads **Strict protection is on**.

Note: If the toggle slider in step 5 is grayed out, click on **Manage protection settings**
instead and configure the policy settings according to [Use the Microsoft 365 Defender portal to assign Standard and Strict preset security policies to users \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#use-the-microsoft-365-defender-portal-to-assign-standard-and-strict-preset-security-policies-to-users).

#### MS.DEFENDER.1.2v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Select **Manage protection settings** under either **Standard protection**
   or **Strict protection**.
6. On the **Apply Exchange Online Protection** page, select **All recipients**.
7. (Optional) Under **Exclude these recipients**, add **Users** and **Groups**
   to be exempted from the preset policies.
8. Select **Next** on each page until the **Review and confirm your changes** page.
9. On the **Review and confirm your changes** page, select **Confirm**.

#### MS.DEFENDER.1.3v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under either **Standard protection** or **Strict protection**, select **Manage
   protection settings**.
6. Select **Next** until you reach the **Apply Defender for Office 365 protection** page.
7. On the **Apply Defender for Office 365 protection** page, select **All recipients**.
8. (Optional) Under **Exclude these recipients**, add **Users** and **Groups**
   to be exempted from the preset policies.
9. Select **Next** on each page until the **Review and confirm your changes** page.
10. On the **Review and confirm your changes** page, select **Confirm**.

#### MS.DEFENDER.1.4v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under **Strict protection**, select **Manage protection settings**.
6. On the **Apply Exchange Online Protection** page, select **Specific recipients**.
7. Add all sensitive accounts via the **User** and **Group** boxes using the
   names of mailboxes, users, contacts, M365 groups, and distribution groups.
8. Select **Next** on each page until the **Review and confirm your changes** page.
9. On the **Review and confirm your changes** page, select **Confirm**.

#### MS.DEFENDER.1.5v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under **Strict protection**, select **Manage protection settings**.
6. Select **Next** until you reach the **Apply Defender for Office 365 protection** page.
7. On the **Apply Defender for Office 365 protection** page, select
   **Specific recipients** or **Previously selected recipients** if sensitive
   accounts were already set on the EOP page.
8. If adding sensitive accounts separately via **Specific recipients**, add all
   sensitive accounts via the **User** and **Group** boxes using the names of
   mailboxes, users, contacts, M365 groups, and distribution groups.
9. (Optional) Under **Exclude these recipients**, add **Users** and **Groups**
   to be exempted from the preset policies.
10. Select **Next** on each page until the **Review and confirm your changes** page.
11. On the **Review and confirm your changes** page, select **Confirm**.

## 2. Impersonation Protection
Impersonation protection checks incoming emails to see if the sender
address is similar to the users or domains on an agency-defined list. If
the sender address is significantly similar, as to indicate an
impersonation attempt, the email is quarantined.

### Policies
#### MS.DEFENDER.2.1v1
User impersonation protection SHOULD be enabled for sensitive accounts in both the standard and strict preset policies.

<!--Policy: MS.DEFENDER.2.1v1; Criticality: SHOULD -->
- _Rationale:_ User impersonation, especially of users with access to sensitive or high-value information and resources, has the potential to result in serious harm. Impersonation protection mitigates this risk. By configuring impersonation protection in both preset policies, administrators can help protect email recipients from impersonated emails, regardless of whether they are added to the standard or strict policy.
- _Last modified:_ June 2023
- _Note:_ The standard and strict preset security policies must be enabled to
          protect accounts.

#### MS.DEFENDER.2.2v1
Domain impersonation protection SHOULD be enabled for domains owned by the agency in both the standard and strict preset policies.

<!--Policy: MS.DEFENDER.2.2v1; Criticality: SHOULD -->
- _Rationale:_ Configuring domain impersonation protection for all agency domains reduces the risk of a user being deceived by a look-alike domain. By configuring impersonation protection in both preset policies, administrators can help protect email recipients from impersonated emails, regardless of whether they are added to the standard or strict policy.
- _Last modified:_ June 2023
- _Note:_ The standard and strict preset security policies must be enabled to
          protect agency domains.

#### MS.DEFENDER.2.3v1
Domain impersonation protection SHOULD be added for important partners in both the standard and strict preset policies.

<!--Policy: MS.DEFENDER.2.3v1; Criticality: SHOULD -->
- _Rationale:_ Configuring domain impersonation protection for domains owned by important partners reduces the risk of a user being deceived by a look-alike domain. By configuring impersonation protection in both preset policies, administrators can help protect email recipients from impersonated emails, regardless of whether they are added to the standard or strict policy.
- _Last modified:_ June 2023
- _Note:_ The standard and strict preset security policies must be enabled to
          protect partner domains.

### Resources

- [Impersonation settings in anti-phishing policies in Microsoft Defender for Office 365 \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-about?view=o365-worldwide#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365)
- [Use the Microsoft 365 Defender portal to assign Standard and Strict preset security policies to users \| Microsoft Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#use-the-microsoft-365-defender-portal-to-assign-standard-and-strict-preset-security-policies-to-users)

### License Requirements

- Impersonation protection and advanced phishing thresholds require
  Defender for Office 365 Plan 1 or 2. These are included with E5 and G5
  and are available as add-ons for E3 and G3. As of April 25, 2023,
  anti-phishing for user and domain impersonation and spoof intelligence
  are not yet available in M365 Government Community Cloud (GCC High) and Department of Defense (DoD) environments. See [Platform features \|
  Microsoft
  Learn](https://learn.microsoft.com/en-us/office365/servicedescriptions/office-365-platform-service-description/office-365-us-government/office-365-us-government#platform-features)
  for current offerings.

### Implementation

#### MS.DEFENDER.2.1v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under either **Standard protection** or **Strict protection**, select **Manage
   protection settings**.
6. Select **Next** until you reach the **Impersonation Protection** page, then
   select **Next** once more.
7. On the **Protected custom users** page, add a name and valid email address for each
   sensitive account and click **Add** after each.
8. Select **Next** until you reach the **Trusted senders and domains** page.
9. (Optional) Add specific email addresses here to not flag as impersonation
   when sending messages and prevent false positives. Click **Add** after each.
10. Select **Next** on each page until the **Review and confirm your changes** page.
11. On the **Review and confirm your changes** page, select **Confirm**.

#### MS.DEFENDER.2.2v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under either **Standard protection** or **Strict protection**, select **Manage
   protection settings**.
6. Select **Next** until you reach the **Impersonation Protection** page, then
   select **Next** once more.
7. On the **Protected custom domains** page, add each agency domain
   and click **Add** after each.
8. Select **Next** until you reach the **Trusted senders and domains** page.
9. (Optional) Add specific domains here to not flag as impersonation when
   sending messages and prevent false positives. Click **Add** after each.
10. Select **Next** on each page until the **Review and confirm your changes** page.
11. On the **Review and confirm your changes** page, select **Confirm**.

#### MS.DEFENDER.2.3v1 Instructions

1. Sign in to **Microsoft 365 Defender**.
2. In the left-hand menu, go to **Email & Collaboration** > **Policies & Rules**.
3. Select **Threat Policies**.
4. From the **Templated policies** section, select **Preset Security Policies**.
5. Under either **Standard protection** or **Strict protection**, select **Manage
   protection settings**.
6. Select **Next** until you reach the **Impersonation Protection** page, then
   select **Next** once more.
7. On the **Protected custom domains** page, add each partner domain
   and click **Add** after each.
8. Select **Next** on each page until the **Review and confirm your changes** page.
9. On the **Review and confirm your changes** page, select **Confirm**.

## 3. Safe Attachments

The Safe Attachments feature will scan messages for attachments with malicious
content. All messages with attachments not already flagged by anti-malware
protections in EOP are downloaded to a Microsoft virtual environment for
further analysis. Safe Attachments then uses machine learning and other
analysis techniques to detect malicious intent. While Safe Attachments for
Exchange Online is automatically configured in the preset policies, separate
action is needed to enable it for other products.

### Policies
#### MS.DEFENDER.3.1v1
Safe attachments SHOULD be enabled for SharePoint, OneDrive, and Microsoft Teams.

<!--Policy: MS.DEFENDER.3.1v1; Criticality: SHOULD -->
- _Rationale:_ Clicking malicious links makes users vulnerable to attacks, and this danger is not limited to links in emails. Other Microsoft products, such as Microsoft Teams, can be used to present users with malicious links. As such, it is important to protect users on these other Microsoft products as well.
- _Last modified:_ June 2023

### Resources

- [Safe Attachments in Microsoft Defender for Office 365 \| Microsoft
  Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about?view=o365-worldwide#safe-attachments-policy-settings)

- [Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft
  Teams \| Microsoft
  Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure?view=o365-worldwide)

### License Requirements

- Safe attachments require Defender for Office 365 Plan 1 or 2. These are included with
  E5 and G5 and are available as add-ons for E3 and G3.

### Implementation

#### MS.DEFENDER.3.1v1 Instructions
To enable Safe Attachments for SharePoint, OneDrive, and Microsoft
Teams, follow the instructions listed at [Turn on Safe Attachments for
SharePoint, OneDrive, and Microsoft Teams \| Microsoft
Learn](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure?view=o365-worldwide).

1.  Sign in to **Microsoft 365 Defender**.

2.  Under **Email & collaboration**, select **Policies & rules**.

3.  Select **Threat policies**.

4.  Under **Policies**, select **Safe Attachments**.

5.  Select **Global settings**.

6.  Toggle the **Turn on Defender for Office 365 for SharePoint, OneDrive, and
    Microsoft Teams** slider to **On**.

## 4. Data Loss Prevention

There are several approaches to securing sensitive information, such
as warning users, encryption, or blocking attempts to share. Agency
policies for sensitive information, such as personally identifiable
information (PII), should dictate how that information is handled and
inform associated data loss prevention (DLP) policies. Defender can detect
sensitive information and associates a default confidence level with
this detection based on the sensitive information type matched.
Confidence levels are used to reduce false positives in detecting access
to sensitive information. Agencies may choose to use the default
confidence levels or adjust the levels in custom DLP policies to fit
their environment and needs.

### Policies
#### MS.DEFENDER.4.1v1
A custom policy SHALL be configured to protect PII and sensitive information, as defined by the agency. At a minimum, credit card numbers, U.S. Individual Taxpayer Identification Numbers (ITIN), and U.S. Social Security numbers (SSN) SHALL be blocked.

<!--Policy: MS.DEFENDER.4.1v1; Criticality: SHALL -->
- _Rationale:_ Users may inadvertently share sensitive information with
               others who should not have access to it. DLP policies
               provide a way for agencies to detect and prevent
               unauthorized disclosures.
- _Last modified:_ June 2023

#### MS.DEFENDER.4.2v1
The custom policy SHOULD be applied to Exchange, OneDrive, SharePoint, Teams chat, and Devices.

<!--Policy: MS.DEFENDER.4.2v1; Criticality: SHOULD -->
- _Rationale:_ Unauthorized disclosures may happen through M365 services
               or endpoint devices. DLP policies should cover all
               affected locations to be effective.
- _Last modified:_ June 2023
- _Note:_ The custom policy referenced here is the same policy
          configured in [MS.DEFENDER.4.1v1](#msdefender41v1).
#### MS.DEFENDER.4.3v1
The action for the custom policy SHOULD be set to block sharing sensitive information with everyone.

<!--Policy: MS.DEFENDER.4.3v1; Criticality: SHOULD -->
- _Rationale:_ Access to sensitive information should be prohibited unless
               explicitly allowed. Specific exemptions can be made based
               on agency policies and valid business justifications.
- _Last modified:_ June 2023
- _Note:_ The custom policy referenced here is the same policy
          configured in [MS.DEFENDER.4.1v1](#msdefender41v1).

#### MS.DEFENDER.4.4v1
Notifications to inform users and help educate them on the proper use of sensitive information SHOULD be enabled in the custom policy.

<!--Policy: MS.DEFENDER.4.4v1; Criticality: SHOULD -->
- _Rationale:_ Some users may not be aware of agency policies on
               proper use of sensitive information. Enabling
               notifications provides positive feedback to users when
               accessing sensitive information.
- _Last modified:_ June 2023
- _Note:_ The custom policy referenced here is the same policy
          configured in [MS.DEFENDER.4.1v1](#msdefender41v1).

#### MS.DEFENDER.4.5v1
A list of apps that are restricted from accessing files protected by DLP policy SHOULD be defined.

<!--Policy: MS.DEFENDER.4.5v1; Criticality: SHOULD -->
- _Rationale:_ Some apps may inappropriately share accessed files or not
               conform to agency policies for access to sensitive
               information. Defining a list of those apps makes it
               possible to use DLP policies to restrict those apps' access
               to sensitive information on endpoints using Defender.
- _Last modified:_ June 2023

#### MS.DEFENDER.4.6v1
The custom policy SHOULD include an action to block access to sensitive
information by restricted apps and unwanted Bluetooth applications.

<!--Policy: MS.DEFENDER.4.6v1; Criticality: SHOULD -->
- _Rationale:_ Some apps may inappropriately share accessed files
               or not conform to agency policies for access to sensitive
               information. Defining a DLP policy with an action to block
               access from restricted apps and unwanted Bluetooth
               applications prevents unauthorized disclosure by those
               programs.
- _Last modified:_ June 2023
- _Note:_
  - The custom policy referenced here is the same policy
    configured in [MS.DEFENDER.4.1v1](#msdefender41v1).
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

#### MS.DEFENDER.4.1v1 Instructions

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

#### MS.DEFENDER.4.2v1 Instructions

See [MS.DEFENDER.4.1v1 Instructions](#msdefender41v1-instructions) step 8
   for details on enforcing DLP policy in specific M365 service locations.

#### MS.DEFENDER.4.3v1 Instructions

See [MS.DEFENDER.4.1v1 Instructions](#msdefender41v1-instructions) steps
   15-17 for details on configuring DLP policy to block sharing sensitive
   information with everyone.

#### MS.DEFENDER.4.4v1 Instructions

See [MS.DEFENDER.4.1v1 Instructions](#msdefender41v1-instructions) steps
   18-19 for details on configuring DLP policy to notify users when accessing
   sensitive information.

#### MS.DEFENDER.4.5v1 Instructions

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

#### MS.DEFENDER.4.6v1 Instructions

If restricted app and unwanted Bluetooth app restrictions are desired,
associated devices must be onboarded with Defender for Endpoint
before the instructions below can be completed.

1. Sign in to the **Microsoft Purview compliance portal**.

2. Under **Solutions**, select **Data loss prevention**.

3. Select **Policies** from the top of the page.

4. Find the custom DLP policy configured under
   [MS.DEFENDER.4.1v1 Instructions](#msdefender41v1-instructions) in the list
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

## 5. Alerts

There are several pre-built alert policies available pertaining to
various apps in the M365 suite. These alerts give administrators better
real-time insight into possible security incidents. Guidance on specific alerts to configure can be found in the linked section of the CISA M365 Security Configuration Baseline for Exchange Online.

- [MS.EXO.16.1v1 \| CISA M365 Security Configuration Baseline for Exchange Online](./exo.md#msexo161v1)



**`TLP:CLEAR`**
