"""
utils/classifier.py — spaCy NER-based component classifier.

Uses spaCy's pre-trained 'en_core_web_sm' model (Named Entity Recognition)
to classify message spans into: name / number / id / text.

spaCy entity labels → component types:
  PERSON, ORG, GPE, LOC, FAC, NORP   → name
  MONEY, PERCENT, QUANTITY, ORDINAL   → number
  CARDINAL with 8+ digits             → id
  CARDINAL (shorter)                  → number
  DATE, TIME                          → text  (fallback, not sensitive enough for own key)
  Everything else / non-entities      → text

Fallback: if spaCy is unavailable, falls back to the original regex classifier.
"""

import re
from dataclasses import dataclass

# spaCy NER label → component type mapping
_NER_TO_TYPE: dict[str, str] = {
    "PERSON":   "name",
    "ORG":      "name",
    "GPE":      "name",   # geo-political entity (cities, countries)
    "LOC":      "name",
    "FAC":      "name",   # facilities (airports, buildings)
    "NORP":     "name",   # nationalities, groups
    "MONEY":    "number",
    "PERCENT":  "number",
    "QUANTITY": "number",
    "ORDINAL":  "number",
    "DATE":     "text",
    "TIME":     "text",
    "EVENT":    "text",
    "WORK_OF_ART": "text",
    "LANGUAGE": "text",
}


@dataclass
class Component:
    seq: int
    type: str   # "name" | "number" | "id" | "text"
    value: str


_nlp = None  # cached model — load once, reuse forever


def _load_spacy():
    """Load spaCy model on first call, return cached instance afterwards."""
    global _nlp
    if _nlp is not None:
        return _nlp
    import spacy  # noqa: PLC0415
    try:
        _nlp = spacy.load("en_core_web_sm")
        return _nlp
    except OSError:
        raise OSError(
            "spaCy model not found. Run: python -m spacy download en_core_web_sm"
        )


def _type_for_cardinal(text: str) -> str:
    """For CARDINAL entities: 8+ consecutive digits -> id, otherwise -> number."""
    digits_only = re.sub(r"[^0-9]", "", text)
    return "id" if len(digits_only) >= 8 else "number"


# ── Regex rules for gap sub-classification ────────────────────────────────────
# Applied inside text gaps that spaCy didn't tag as a named entity.

_RE_ID       = re.compile(r'\b\d{8,}\b')          # 8+ consecutive digits
_RE_NUMBER   = re.compile(r'\$\s?\d[\d,]*(?:\.\d+)?|\b\d[\d,]*\.\d+\b|\b\d{1,7}\b')
_RE_NAME     = re.compile(r'\b[A-Z][a-z]{1,}\b')  # Single capitalised word


def _classify_token(token: str) -> str:
    """Classify a single stripped token using regex rules."""
    stripped = token.strip(".,;:!?\"'()")
    if _RE_ID.fullmatch(stripped):     return "id"
    if _RE_NUMBER.fullmatch(stripped): return "number"
    if _RE_NAME.fullmatch(stripped):   return "name"
    return "text"


def _classify_gap(original_text: str, gap_start: int, gap_end: int) -> list[tuple[int, int, str]]:
    """
    Sub-classify a gap (text region not covered by a spaCy entity) using
    the regex rules.  This catches long digit sequences, currency values,
    and capitalised names that spaCy's small model may miss.

    Returns a list of (start_char, end_char, type) tuples.
    """
    result: list[tuple[int, int, str]] = []
    # Split into alternating whitespace / non-whitespace segments
    for match in re.finditer(r'(\s+|\S+)', original_text[gap_start:gap_end]):
        seg_start = gap_start + match.start()
        seg_end   = gap_start + match.end()
        segment   = match.group()
        if segment.strip():
            comp_type = _classify_token(segment)
        else:
            comp_type = "text"   # pure whitespace → text
        result.append((seg_start, seg_end, comp_type))
    return result


def classify_message(text: str) -> list[Component]:
    """
    Classify *text* into typed components using spaCy NER.

    Approach:
      1. Run spaCy NER over the full text.
      2. Named entities get their type from _NER_TO_TYPE mapping.
      3. Non-entity text between entities is classified as 'text'.
      4. Adjacent same-type spans are merged.
    """
    if not text.strip():
        return []

    nlp = _load_spacy()
    doc = nlp(text)

    # Build list of (start_char, end_char, type) for all regions
    entity_spans: list[tuple[int, int, str]] = []

    for ent in doc.ents:
        if ent.label_ == "CARDINAL":
            comp_type = _type_for_cardinal(ent.text)
        else:
            comp_type = _NER_TO_TYPE.get(ent.label_, "text")

        # Only use spaCy's entity if it maps to a non-text type.
        # Entities that map to 'text' (DATE, TIME, LANGUAGE, etc.) are
        # skipped so the regex gap-filler can re-classify them correctly.
        # This handles the case where spaCy mislabels a digit sequence as DATE.
        if comp_type != "text":
            entity_spans.append((ent.start_char, ent.end_char, comp_type))

    # Sort entities by position
    entity_spans.sort(key=lambda x: x[0])

    # Fill gaps between entities — sub-classify with regex (hybrid mode)
    all_spans: list[tuple[int, int, str]] = []
    prev_end = 0

    for start, end, comp_type in entity_spans:
        if start > prev_end:
            # Sub-classify the gap with regex to catch IDs/numbers spaCy missed
            all_spans.extend(_classify_gap(text, prev_end, start))
        all_spans.append((start, end, comp_type))
        prev_end = end

    # Trailing gap
    if prev_end < len(text):
        all_spans.extend(_classify_gap(text, prev_end, len(text)))

    if not all_spans:
        return [Component(seq=1, type="text", value=text.strip())]

    # Merge adjacent same-type spans, preserving the original text slice
    components: list[Component] = []
    seq = 1
    cur_type = all_spans[0][2]
    cur_start = all_spans[0][0]
    cur_end = all_spans[0][1]

    for start, end, span_type in all_spans[1:]:
        if span_type == cur_type:
            cur_end = end  # extend the current span
        else:
            # Keep raw slice including surrounding whitespace for exact reconstruction
            components.append(Component(seq=seq, type=cur_type, value=text[cur_start:cur_end]))
            seq += 1
            cur_type = span_type
            cur_start = start
            cur_end = end

    components.append(Component(seq=seq, type=cur_type, value=text[cur_start:cur_end]))
    return components


def unique_types(components: list[Component]) -> list[str]:
    """Return deduplicated list of component types present in *components*."""
    seen = []
    for c in components:
        if c.type not in seen:
            seen.append(c.type)
    return seen
