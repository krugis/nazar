# Third-party licenses

Nazar itself is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). It depends on, or
can be used with, the following third-party software and data. None of the models or databases
below are bundled with Nazar; users download them separately.

## Python dependencies

| Package | License | Use |
|---|---|---|
| [httpx](https://github.com/encode/httpx) | BSD-3-Clause | HTTP client (LAPI, Ollama, CTI, Telegram) |
| [pydantic](https://github.com/pydantic/pydantic) | MIT | config and data validation |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | config file parsing |
| [geoip2](https://github.com/maxmind/GeoIP2-python) (optional `geoip` extra) | Apache-2.0 | GeoLite2 lookups |

Development-only tools (pytest, pytest-asyncio, respx, ruff, mypy) are not distributed with Nazar.

## Models

| Model | License | Notes |
|---|---|---|
| [IBM Granite 4.0 Micro-H](https://ollama.com/library/granite4) (`granite4:micro-h`) | Apache-2.0 | default triage model, pulled by the user through Ollama |

Any other model configured in `analyst.model` is subject to its own license.

## Data

| Data | License | Notes |
|---|---|---|
| MaxMind GeoLite2 Country / ASN | GeoLite2 End User License Agreement | optional; downloaded by the user with a free MaxMind account. Attribution: "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com." |
| CrowdSec CTI | CrowdSec terms of service | optional API, used with the user's own key |

## Services

CrowdSec is a trademark of CrowdSec SAS. Ollama and Telegram are used through their public APIs.
Nazar is an independent project and is not affiliated with or endorsed by any of these.
