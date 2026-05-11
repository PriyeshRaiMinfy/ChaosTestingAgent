# Utils

Shared infrastructure used by every scanner. Currently one module: [`aws_session.py`](aws_session.py).

---

## `AWSSession` — [`aws_session.py`](aws_session.py)

A thin wrapper around `boto3.Session` that adds:

- **Named-profile support** — reads from `~/.aws/credentials` by profile name
- **Client caching** — one client object per `(service, region)` pair, reused across calls
- **Consistent retry config** — adaptive mode, 10 max attempts, baked into every client
- **Account ID resolution** — via `sts:GetCallerIdentity`, cached after first call
- **Region enumeration** — via `ec2:DescribeRegions`, cached after first call

### Usage

```python
from breakbot.utils import AWSSession

sess = AWSSession(profile="breakbot", region="us-east-1")

# Resolve account ID (cached)
print(sess.account_id)  # "123456789012"

# Get a boto3 client — cached, so repeated calls are free
ec2_us = sess.client("ec2", region="us-east-1")
ec2_eu = sess.client("ec2", region="eu-west-1")
iam    = sess.client("iam", region="us-east-1")

# List all enabled regions in the account (cached)
regions = sess.enabled_regions()  # ["ap-northeast-1", "eu-west-1", "us-east-1", ...]
```

### Retry configuration

```python
_BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)
```

**Adaptive retry** means botocore tracks the server's error rate and exponentially
backs off when AWS starts throttling. This is important when scanning large accounts
with thousands of resources across 15+ regions — you will hit `ThrottlingException`
without this.

10 max attempts is intentionally generous because BreakBot is read-only and there
is no risk of write-side side effects from retrying.

### Client caching

```
Without cache:  15 regions × 6 services = 90 client objects created
With cache:     each (service, region) pair created once and reused
```

Client creation in boto3 involves parsing service models, setting up auth handlers,
and establishing connection pools. On a full multi-region scan, caching saves
several seconds of startup overhead and memory.

### Design notes

**Why not `@lru_cache` on `enabled_regions`?**
`lru_cache` on an instance method holds a reference to `self` in the cache key,
preventing garbage collection even after the `AWSSession` goes out of scope.
The simple fix is an explicit `_regions_cache: list[str] | None = None` attribute —
same result, no memory leak.

**Why no async?**
boto3 doesn't have a first-class async client. `aioboto3` exists but adds
significant complexity. For the scanning use case (one account, sequential
regions) the throughput is fine synchronously. If we need parallelism,
`concurrent.futures.ThreadPoolExecutor` around `scanner.scan()` is the right
approach — the boto3 clients are thread-safe.
