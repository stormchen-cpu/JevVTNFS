from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, List, Tuple


def deterministic_group_split(
    items: List[Dict[str, Any]],
    group_key: str = "issue_key",
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Splits items into train, validation, and test sets with strict group-level isolation.
    Ensures that all items sharing the same group_key (e.g. issue_key / case lineage)
    are placed entirely in the same split to prevent data leakage.
    """
    if train_ratio + val_ratio > 1.0:
        raise ValueError("Sum of train_ratio and val_ratio must not exceed 1.0.")

    # Group items by group_key
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        k = str(item.get(group_key, item.get("issue_key", "default_group")))
        groups.setdefault(k, []).append(item)

    # Sort group keys for deterministic behavior
    sorted_group_keys = sorted(groups.keys())

    # Deterministic shuffle using seed
    rng = random.Random(seed)
    rng.shuffle(sorted_group_keys)

    n_groups = len(sorted_group_keys)
    train_end = int(n_groups * train_ratio)
    val_end = train_end + int(n_groups * val_ratio)

    train_groups = set(sorted_group_keys[:train_end])
    val_groups = set(sorted_group_keys[train_end:val_end])
    test_groups = set(sorted_group_keys[val_end:])

    # Verify zero leakage across groups
    assert not (train_groups & val_groups), "Leakage detected between train and val groups!"
    assert not (train_groups & test_groups), "Leakage detected between train and test groups!"
    assert not (val_groups & test_groups), "Leakage detected between val and test groups!"

    train_items: List[Dict[str, Any]] = []
    val_items: List[Dict[str, Any]] = []
    test_items: List[Dict[str, Any]] = []

    for k, item_list in groups.items():
        if k in train_groups:
            train_items.extend(item_list)
        elif k in val_groups:
            val_items.extend(item_list)
        else:
            test_items.extend(item_list)

    return train_items, val_items, test_items
