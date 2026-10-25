"""Read `cscli decisions list -o json` on stdin and answer one question (e2e helper).

    count            number of active decisions created by Nazar
    banned <ip>      exit 1 if Nazar has an active decision on <ip>
"""

import json
import sys

alerts = json.load(sys.stdin) or []
nazar = [
    d
    for alert in alerts
    for d in alert.get("decisions") or []
    if d.get("scenario") == "nazar/ai-triage"
]
if sys.argv[1] == "count":
    print(len(nazar))
elif sys.argv[1] == "banned":
    sys.exit(1 if any(d.get("value") == sys.argv[2] for d in nazar) else 0)
