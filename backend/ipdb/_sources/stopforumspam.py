"""StopForumSpam toxic IP CIDR list — spam-range source.

StopForumSpam publishes `toxic_ip_cidr.txt`: ~60 network ranges declared as
"only usable for abuse" (forum/comment spam, credential stuffing). Free, no
auth, daily update. Opens the `spam` classification axis, which previously had
no dedicated emitter — only side-channel hits from blocklist_de `mail` codes
and MISP title heuristics. Single-source by definition: corroboration on the
`spam` axis begins only if a second spam source is added later.

  https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt
"""
from ._base import IpListSource


class StopForumSpamSource(IpListSource):
    name = "stopforumspam"
    url = "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt"
    filename = "stopforumspam.txt"
    fields = ("is_malicious",)
    classification_type = "spam"
    verdict = "malicious"
    stale_days = 1
    reliability = 0.70
    authoritative_for = []
