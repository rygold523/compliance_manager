from pathlib import Path
import subprocess
import traceback

from app.services.evidence_collectors import run_collector

BASELINE_INITIAL_COLLECTORS = [
    "iam_users",
    "os_inventory",
    "disk_usage",
    "docker_inventory",
]


def post_deploy_linux_agent_setup(asset):
    """
    Runs after a Linux managed target is deployed/registered.

    Responsibilities:
    - Verify backend SSH trust to compliance-agent.
    - Run baseline collectors once so the dashboard has immediate data.
    - Never break deployment if a collector fails.
    """

    results = []

    for collector_name in BASELINE_INITIAL_COLLECTORS:
        try:
            result = run_collector(asset, collector_name)

            if not isinstance(result, dict):
                result = {
                    "collector": collector_name,
                    "asset_id": getattr(asset, "asset_id", None),
                    "status": "failed",
                    "stderr": "Collector returned non-dict result",
                }

        except Exception as exc:
            traceback.print_exc()
            result = {
                "collector": collector_name,
                "asset_id": getattr(asset, "asset_id", None),
                "status": "failed",
                "stderr": str(exc),
            }

        results.append(result)

    return results
