"""Strict YAML loading for frontmatter.

PyYAML's safe loader keeps the LAST occurrence of a duplicated key. In a gate
that reads its evidence from frontmatter that is a fail-open: an OPEN
CRITICAL ``conflicts:`` block followed later by ``conflicts: []`` would pass.
This loader refuses duplicate keys at every nesting level, so such a document
is unparseable (which blocks) rather than quietly rewritten.
"""
from __future__ import annotations

import yaml


class DuplicateKeyError(yaml.YAMLError):
    pass


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            dup = key in seen
        except TypeError:           # an unhashable key; let PyYAML report it
            continue
        if dup:
            raise DuplicateKeyError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_strict(text: str):
    """yaml.safe_load, except a duplicate mapping key raises DuplicateKeyError."""
    # _StrictLoader subclasses SafeLoader and adds only the duplicate check,
    # so this is safe_load with one more refusal.
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506  # nosec B506
