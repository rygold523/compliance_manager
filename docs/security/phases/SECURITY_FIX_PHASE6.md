# Security Fix Phase 6: Login Failure Throttling

This phase removes the username-enumeration and account-denial behavior from
local login failures.

- Every failed login state performs an Argon2 verification and returns the
  same HTTP 401 response and message.
- Password failures no longer create or extend an account-wide lock.
- Persistent throttles apply to the source address and to the
  source-address/username pair.
- Unknown usernames update only the source throttle, preventing arbitrary
  username traffic from creating an unbounded set of throttle rows.
- Backoff grows exponentially and is capped by configuration.
- A successful login clears only its source-address/username throttle; it does
  not clear a source-wide abuse throttle.
- Internal audit reasons remain available to authorized administrators.

Existing `locked_until` values remain honored until they expire or an
administrator clears them, but they no longer produce a distinguishable
response.
