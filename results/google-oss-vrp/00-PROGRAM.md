# Google OSS VRP — programme analysis, 2026-09-25

Source: `github.com/google/bughunters` (Google's own published tier list and rules).

---

## Why this target, after three clean negatives elsewhere

| | Exoscale | Google web VRP | Adobe | **OSS VRP (Actions)** |
|---|---|---|---|---|
| Cost to test | card pre-auth | — | paywalled at $11.49/mo | **£0** |
| Accounts required | 2 orgs | — | 2, metered | **none** |
| Rate limits / IP blocks | 10 req/s | yes | auto-IP-block | **none** |
| Works offline on the Pi | no | no | no | **yes** |
| "Intended behaviour" risk | high | killed 3 reports | high | **low — a leaked secret is never intended** |
| Top reward | €5,000 | — | $15,000 | **$31,337** |

Every previous engagement failed on *access* (paywall, card, tenancy) or on *"working as
intended"*. Neither applies to a public YAML file that hands a repository secret to an
unapproved outside contributor.

## Reward table (from the published rules)

| Category | OT0 Flagship | OT1 Important | OT2 Standard | OT3 |
|---|---|---|---|---|
| **Supply chain compromises** | **$3,133.7 – $31,337** | **$1,337 – $13,337** | $500 – $3,133.7 | — |
| Product vulnerabilities | $500 – $7,500 | $101 – $3,133.7 | **not eligible** | — |

**Supply chain pays 4–10× product vulnerabilities.** That single fact sets the target.

## What counts as supply chain (their words)

> *"The program also covers **repository configuration settings (e.g. GitHub actions**, access
> control rules, GitHub application configurations)."*

Named examples:
- Ability to modify or submit code on main branches
- **Vulnerabilities in Google OSS GitHub Actions configuration**
- Insecure configuration of a project's GCP build environment
- **Disclosure of package manager credentials** for publishing artifacts
- Compromise of cryptographic signing keys

## THE BAR — read this before writing anything

> *"You must be able to demonstrate that the vulnerability is exploitable, **bypassing the
> requirement that external contributors must first have PRs approved**… If your vulnerability
> will only trigger after approval by a maintainer, the vulnerability will be considered for
> 'Credit' as it will be treated only as an insider risk."*

**A workflow that only runs after a maintainer clicks approve is worth credit, not money.** The
whole game is finding execution paths that run *without* that click — `pull_request_target`,
`issue_comment`, `workflow_run`, `issues`, `discussion`, scheduled jobs consuming PR data.

## Other acceptance rules worth knowing

- **Memory corruption in OT0/OT1 needs OSS-Fuzz repro steps or a merged patch.** High bar —
  avoid this class.
- **Non-memory-corruption vulnerabilities in OT0/OT1 need no merged patch.** Actions
  misconfiguration sits here. Lower bar.
- OT2/OT3: product vulns and "other security issues" earn **no money at all**. Only hunt the
  published OT0/OT1 list.
- Third-party dependency issues must be fixed upstream first, then held 30 days.
- Vulnerabilities in GitHub/CI *platforms themselves* are out of scope — only Google's
  *configuration* of them.

## Scope — 71 GitHub repos (25 OT0, 46 OT1)

**OT0 (Flagship):**
```
angular/angular · angular/angular-cli · angular/components · angular/dev-infra
bazelbuild/bazel · bazelbuild/bazel-central-registry · bazelbuild/continuous-integration
golang/go · golang/crypto · golang/net · golang/sys · golang/text · golang/tools
golang/image · golang/sync
google/guava · google/gson · google/gvisor · GoogleContainerTools/distroless
protocolbuffers/protobuf · tink-crypto/tink-cc · tink-crypto/tink-go · tink-crypto/tink-java
flutter/flutter · openthread/openthread
```

**OT1 — the newest code Google ships (best duplicate odds):**
```
google-gemini/gemini-cli
google/adk-python · adk-go · adk-java · adk-js · adk-kotlin      (Agent Development Kit)
ChromeDevTools/chrome-devtools-mcp                                (MCP server)
project-oak/oak · google/osv-scanner · google/clusterfuzz · google/zerocopy
jax-ml/jax · keras-team/keras · openxla/xla · dart-lang/sdk · flutter/devtools
```

Non-GitHub (different workflow, deprioritise): `fuchsia.googlesource.com/fuchsia`,
`gerrit.googlesource.com/gerrit`.

## Honest risks

- These repos are audited, and Actions security is a known hunting ground. **Duplicate risk is
  the main threat**, exactly as with Adobe.
- The OT0 projects are the most scrutinised. The **OT1 AI/agent repos are newer** and a better
  bet on that basis alone.
- A finding gated behind maintainer approval pays nothing. Check the trigger first, always.
