# Salt & Pepper Analysis

This document compares the security implications of per-user salts versus a global system pepper.

## Overview

| Feature | Salt | Pepper |
|----------|------|--------|
| Unique per user | ✅ | ❌ (same for all) |
| Stored in DB | ✅ | ❌ (kept secret in app config) |
| Protects against precomputed attacks | ✅ | ✅ |
| Increases brute-force cost | ✅ | ✅ (requires guessing secret) |

### Example Test

Run simple benchmark:

```python
# Example: test hash times
from app.crypto_utils import hash_password
import time

for algo in ["sha256", "sha3", "bcrypt", "argon2"]:
    t0 = time.time()
    hash_password(algo, "test1234")
    print(algo, round(time.time() - t0, 3), "seconds")
