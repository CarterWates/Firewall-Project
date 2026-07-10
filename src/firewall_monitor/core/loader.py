from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from firewall_monitor.core.policy import FirewallPolicy


class PolicyLoadError(RuntimeError):
    """Raised when a policy file cannot be read as YAML policy data."""


def load_policy_file(path: Path) -> FirewallPolicy:
    """Load and validate a firewall policy from a YAML file."""

    if not path.exists():
        msg = f"policy file does not exist: {path}"
        raise PolicyLoadError(msg)
    if not path.is_file():
        msg = f"policy path is not a file: {path}"
        raise PolicyLoadError(msg)

    try:
        raw_data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        msg = f"policy file is not valid YAML: {path}"
        raise PolicyLoadError(msg) from exc

    if raw_data is None:
        msg = f"policy file is empty: {path}"
        raise PolicyLoadError(msg)
    if not isinstance(raw_data, dict):
        msg = "policy file must contain a YAML mapping at the top level"
        raise PolicyLoadError(msg)

    return FirewallPolicy.model_validate(raw_data)
