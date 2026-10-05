# T03 — Mining the archive: SolarCity's legacy API estate

2026-10-06, from Termux. A deliberately different method: **no scanning**.

## Why this, and not more subdomain enumeration

Certificate transparency plus HTTP probing is what every one of the programme's 528 recent
researchers runs, usually with better tooling and a better connection. There is no edge there.

The Internet Archive is a different dataset. It holds twenty years of URLs that were *linked*
at some point — paths that no longer appear anywhere on the live site, so no crawler finds them
today. And it costs Tesla nothing: **not one request reaches their infrastructure.**

```
web.archive.org/cdx/search/cdx?url=<domain>&matchType=domain&fl=original&collapse=urlkey
```

```
tesla.com 40,000 · teslamotors.com 40,000 · tesla.cn 40,000 · solarcity.com 25,864
145,864 unique URLs
112 solarcity.com hosts, many absent from the CT-derived set
```

Hosts the archive knew and certificate transparency did not: `admin`, `customercare`, `dynamo`,
`designpro`, `hives`, `flannel`, `employeereferral`, `gw-test`, `go-int`, `backup-vpn.scfs`,
`api.nc`, `hpp`, `isapi`. Of 112 archived hosts, **8 still answer**:

```
api.solarcity.com         401        api-test.solarcity.com    403
isapi.solarcity.com       500        solarguard.solarcity.com  403
login.solarcity.com       302 -> its own sign-in
secure{,-test}.solarcity.com  302 -> www.tesla.com
warp.solarcity.com        200  (a jQuery redirect stub)
```

## What the archive handed over

Full ASP.NET Help documentation for SolarCity's internal APIs, including endpoint names that
describe exactly what they return:

```
/employee/Help/Api/     GET api/info/contact/{contactid} · info/details/{userId}
                        info/details_email · info/employee/{employeeId}
/solarproposalapi/Help/ GET Utility/BillImage/DealId/{dealId} · proposal/summary/{proposalId}
                        deals/{dealGuid}/loan/applications/primary · milestones/credit
/powerguide/Help/       GET v1.0/customers?IsDetailed&Size&Page      <- paginated customer list
                        v1.0/customers/{CustomerGUID}
                        v1.0/installations?Size&Page
                        v1.0/installations/{GUID}/billing?StartDate&EndDate
                        v1.0/devices?Size&Page · measurements · consumption · groups
```

A paginated customer list and per-installation billing is the most sensitive shape this
engagement has found anywhere.

## The differential that made it worth testing

`api.solarcity.com` answers **401 with a two-byte body to everything**, including a nonexistent
path. That is a blanket edge refusal and normally means there is nothing to see. Except:

```
/__canary__                401      2b
/powerguide/               200  6,135b
/powerguide/Help           200 13,048b     <- live, and outside whatever returns the 401
/powerguide/healthcheck    404  1,917b
```

PowerGuide is reachable past the edge, and its documentation is public. Documentation alone is
not a finding — it is the map. The question is whether the endpoints it maps are guarded.

## The sweep, and the hole in the first pass

Eighteen documented paths, each called with an all-zero GUID that can belong to nobody:

```
customers · customers/{guid} · devices · devices/{guid} · groups · groups/{guid}
installations · installations/{guid} · installations/{guid}/appliances · …/weather
                                                       -> 401 Authorization has been denied
installations/stats/pollutionoffset                    -> 200
grid_transfer · billing · summary · measurements       -> 404 No HTTP resource was found
```

The four 404s were **not** a result. "No HTTP resource matches this URI" means routing failed
before authorisation was ever consulted — those endpoints take mandatory query parameters
(`Period`, `StartTime`, `EndTime`, `StartDate`) and without them the request never reaches the
handler. Reading them as "protected" would have been wrong.

Re-run with the documented parameters, plus the list endpoints and a sentinel:

```
consumption/{guid}?Period&StartTime&EndTime&IncludeCurrent      401
grid_transfer/{guid}?…                                          401
installations/{guid}/billing?StartDate&EndDate                   401
installations/{guid}/summary?…                                   401
installations/{guid}/weather?…                                   401
measurements/{guid}?…                                            401
customers?IsDetailed=false&Size=1&Page=1                         401
installations?Size=1&Page=1                                      401
v1.0/__canary__/{guid}?…                                         404   <- sentinel differs
```

**Every data endpoint enforces authentication, consistently.** The sentinel answers differently,
so the 401s are the application speaking rather than the edge.

### The one unauthenticated endpoint, and why it is not a report

```
GET /powerguide/v1.0/installations/stats/pollutionoffset   200
{"TotalGenerationkWh":53313533381.094,"ConservedGallonsOfWater":15748929000.15, …}
```

Fleet-wide aggregates — total generation, water conserved. No customer, no installation, no
identifier. Tesla publishes figures of this kind itself. Recorded and dropped.

## Still open from this dataset

The archive also documents `/employee/` and `/solarproposalapi/` — contact, user and employee
lookup by id, utility bill images by deal id, loan applications. On `api.solarcity.com` those
paths return the blanket 401 and on `api-test` they 404, so they are not deployed where we can
reach them. `api-dev.solarcity.com` has no DNS.

`api-test.solarcity.com` is worth one more pass: its canary answers 404 while `/deals/swagger/`,
`/milestones/swagger/` and `/sources/swagger/` answer **403 with a 26-byte body** — a different
response, so those three applications are deployed there behind something. The archive holds
real paths for them (`/deals/values`, `/milestones/healthcheck`) that have not been tried.
