# 06: Enricher (`nazar.enrich`)

Adds context to an incident before triage (DESIGN §3.3). Every provider is optional, cached where it
calls out, and can never block triage.

## Files

| File | Contents |
|---|---|
| `base.py` | `EnrichmentProvider` protocol, `Enricher` (runs providers) |
| `alert_geo.py` | country/ASN from CrowdSec's own alert data |
| `cti.py` | CrowdSec CTI smoke client + cache |
| `geoip.py` | MaxMind GeoLite2 lookup (only if the `geoip` extra and a DB path are present) |
| `history.py` | previous incidents and bans for the IP from the store |

## Interface

```python
class EnrichmentProvider(Protocol):
    name: str
    async def enrich(self, incident: Incident, events: Sequence[Event]) -> dict[str, Any]
        # returns a partial Enrichment as a dict; only keys it knows

class Enricher:
    def __init__(self, providers: Sequence[EnrichmentProvider], timeout_s: float = 5.0) -> None
    async def enrich(self, incident: Incident, events: Sequence[Event]) -> Enrichment
```

`Enricher.enrich` runs providers concurrently (`asyncio.gather`), each under its own timeout.
A provider exception or timeout is logged (`enrichment_failed`, provider, error type) and ignored.
Results merge in provider order; **the first non-null value wins**, so order expresses trust:
`alert_geo`, `geoip`, `cti`, `history`. Lists are unioned.

## Providers

### alert_geo
`country`, `asn` from the most recent event that has them. No I/O.

### cti (CrowdSec CTI)
- Enabled only when `crowdsec.cti_api_key_env` names a set variable.
- `GET {cti_url}/smoke/{ip}` with header `X-Api-Key` (verified against `pkg/cticlient` in CrowdSec).
- Normalized and cached in `cti_cache` for `cti_cache_hours`:

| Enrichment field | Smoke response field |
|---|---|
| `cti_reputation` | `reputation` (`malicious`, `suspicious`, `known`, `safe`, `unknown`) |
| `cti_behaviors` | `behaviors[].name` |
| `cti_classifications` | `classifications.classifications[].name` (false positives prefixed `fp:`) |
| `country` | `location.country` |
| `asn` | `"AS{as_num} {as_name}"` |

- `404` → cache `{"reputation": "unknown"}` (IP not known to CTI).
- `429` → do not cache; skip CTI for 5 minutes (circuit open), log once.
- `401/403` → health warning "CTI key rejected", skip CTI until restart.
- All strings pass through `sanitize.clean()` and are length-capped; CTI is third-party data.

### geoip
`geoip2.database.Reader` on `enrich.geoip_country_db` (GeoLite2 Country or City) and
`enrich.geoip_asn_db` (GeoLite2 ASN). Lookups run in a thread. Missing package or file → provider not registered, info log at startup.

### history
From the store: `previous_incidents` = incidents for this IP other than this one within retention;
`previous_bans` = applied Nazar decisions for this IP plus closed incidents where CrowdSec had
banned it.

## Tests

respx CTI fixtures (malicious, 404, 429, 403); cache hit avoids HTTP; provider timeout leaves
fields null; merge precedence; strings sanitized.
