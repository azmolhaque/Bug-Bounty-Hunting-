# F001 evidence manifest — files live on the local machine only

**Nothing in this list is committed.** `env.json` and `config_web.json` both contain live
credentials, and CLAUDE.md §7 forbids pushing secrets to git. This file records what exists and
what each item proves, so the submission can be assembled without the evidence ever entering the
repository.

| Item | Where | What it proves |
|---|---|---|
| `env.json` (5799 b) | local | The complete unauthenticated `https://www.tesla.com/api/findus/env` response, with `"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"` and a blank `gioConfig`. **This is the `.com` proof curl could not get.** |
| `config_web.json` from `.com` (329052 b) | local | Contains `"ip_lookup_service_token": "47216944bba1aa"`, `"use_ip_lookup_service": true`, `"ipInfo": "https://ipinfo.io/geo"`. **Byte-for-byte the same length as the `.cn` copy** — the same file is served from both hosts. |
| `config_web.json` from `.cn` (329052 b) | local | Same, fetched by curl directly. |
| Browser screenshot — `tesla.com/api/findus/env` | local | The Baidu key visible in a browser with the `.com` URL bar showing. |
| Browser screenshot — `tesla.com/.../proxy.php?ip=true` | local | `{"ip":"205.234.27.201","city":"San Jose",…,"org":"AS40913 Quality Technology Services, LLC"}` — a **server-side** ipinfo lookup run by `www.tesla.com`. The strongest single piece of evidence: the leaked token is spent by `.com` production, not just `.cn`. |
| Browser screenshot — `config_web.json` on `.com`, token highlighted 1/1 | local | The token is on the global site. |
| Terminal screenshot — ipinfo with/without token | local | `readme` field appears and disappears; `/me` returns the account. |
| Terminal screenshot — Baidu success beside Google `REQUEST_DENIED` | local | The differential, in one frame. |
| `~/tesla/EVIDENCE.txt` | local | Final run: 2026-10-05 19:35:23 UTC, IP 180.148.212.54, curl 8.21.0. |

## Not evidence for F001

A screenshot showing `Expired or invalid token` from the archived SSO key. Keep it, but it belongs
to the dropped lead in `T03-ARCHIVE.md`, not to this report. Its value is as the record that the
key was **not** live and that no account was accessed.
