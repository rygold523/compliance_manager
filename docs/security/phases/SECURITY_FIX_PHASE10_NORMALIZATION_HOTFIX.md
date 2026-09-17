# Phase 10 Windows normalization hotfix

This hotfix recursively removes only known collector-execution metadata fields
from evidence fingerprint input. It fixes false Windows evidence changes caused
by `raw.collected_at` while retaining observed event timestamps and actual state.

The hotfix does not delete, compact, or modify historical evidence.
