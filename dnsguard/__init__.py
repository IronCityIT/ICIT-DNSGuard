"""Iron City DNS Guard control plane.

The scanner (module_framework) answers "what is wrong with this domain".
This package answers everything that follows from that: which tenant and site a
result belongs to, what policy applies, which threat feed justified a block,
who approved the change, and what evidence proves it.

Nothing in here reaches the network except dnsguard.feeds, and nothing in here
performs a disruptive action without passing through dnsguard.approvals.
"""

__version__ = "1.0.0"
