"""
utils/classifier.py — Rule-based component classifier.

Splits a message string into labelled spans (components) using regex + heuristics.
No external NLP libraries required.

Component types (sensitivity ordering, highest first):
  id      — long digit sequences (e.g., SSN, account number, 8+ digits)
  number  — currency values or plain numbers (floats, ints, currency)
  name    — a single capitalised word standing alone
  text    — everything else (fallback / highest catch-all sensitivity)
"""

import re
from dataclasses import dataclass


@dataclass
class Component:
    seq: int
    type: str   # "name" | "number" | "id" | "text"
    value: str


# ── Regex patterns (order matters: most specific first) ───────────────────────

# 8+ consecutive digits → ID  (SSN without dashes, account numbers, etc.)
_ID_RE = re.compile(r'\b\d{8,}\b')

# Currency: optional $ or leading digits with decimal and optional currency symbol
_CURRENCY_RE = re.compile(r'\$\s?\d[\d,]*(?:\.\d+)?|\b\d[\d,]*\.\d+\b|\b\d{1,7}\b')

# Single capitalised word (Name): starts with uppercase, rest lowercase, 2+ chars
_NAME_RE = re.compile(r'\b[A-Z][a-z]{1,}\b')


def _classify_token(token: str) -> str:
    """Return the type label for a single whitespace-delimited token."""
    stripped = token.strip(".,;:!?\"'()")
    if _ID_RE.fullmatch(stripped):
        return "id"
    if _CURRENCY_RE.fullmatch(stripped):
        return "number"
    if _NAME_RE.fullmatch(stripped):
        return "name"
    return "text"


def classify_message(text: str) -> list[Component]:
    """
    Split *text* into components.  Adjacent tokens of the same type are merged
    into one span so the message isn't over-fragmented.

    Returns a list of Component objects in order.
    """
    tokens = text.split()
    if not tokens:
        return []

    components: list[Component] = []
    seq = 1

    current_type = _classify_token(tokens[0])
    current_tokens = [tokens[0]]

    for token in tokens[1:]:
        t = _classify_token(token)
        if t == current_type:
            current_tokens.append(token)
        else:
            components.append(Component(seq=seq, type=current_type, value=" ".join(current_tokens)))
            seq += 1
            current_type = t
            current_tokens = [token]

    # flush the last group
    components.append(Component(seq=seq, type=current_type, value=" ".join(current_tokens)))

    return components


def unique_types(components: list[Component]) -> list[str]:
    """Return deduplicated list of component types present in *components*."""
    seen = []
    for c in components:
        if c.type not in seen:
            seen.append(c.type)
    return seen
