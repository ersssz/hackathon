"""Attack template loader."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from .models import Attack, AttackCategory


DEFAULT_ATTACKS_DIR = Path(__file__).resolve().parent.parent / "attacks"


def load_attacks(
    attacks_dir: Path | str | None = None,
    categories: Iterable[AttackCategory] | None = None,
) -> list[Attack]:
    """Load attack templates from YAML files.

    Args:
        attacks_dir: directory containing YAML files (one per category).
        categories: if given, only load attacks from these categories.

    Returns:
        List of Attack objects sorted by severity descending.
    """
    root = Path(attacks_dir) if attacks_dir else DEFAULT_ATTACKS_DIR
    if not root.exists():
        raise FileNotFoundError(f"Attacks dir not found: {root}")

    attacks: list[Attack] = []
    for yaml_file in sorted(root.glob("*.yaml")):
        with yaml_file.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for item in data.get("attacks", []):
            atk = Attack(**item)
            if categories is None or atk.category in categories:
                attacks.append(atk)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    attacks.sort(key=lambda a: severity_order.get(a.severity.value, 99))
    return attacks
