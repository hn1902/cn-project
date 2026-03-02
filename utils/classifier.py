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


def _load_spacy():
    """Load spaCy model, raise ImportError if not installed."""
    import spacy  # noqa: PLC0415
    try:
        return spacy.load("en_core_web_sm")
    except OSError:
        raise OSError(
            "spaCy model not found. Run: python -m spacy download en_core_web_sm"
        )


def _type_for_cardinal(text: str) -> str:
    """For CARDINAL entities: 8+ consecutive digits → id, otherwise → number."""
    import re
    digits_only = re.sub(r"[^0-9]", "", text)
    return "id" if len(digits_only) >= 8 else "number"


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
        entity_spans.append((ent.start_char, ent.end_char, comp_type))

    # Sort entities by position
    entity_spans.sort(key=lambda x: x[0])

    # Fill gaps between entities as 'text'
    all_spans: list[tuple[int, int, str]] = []
    prev_end = 0

    for start, end, comp_type in entity_spans:
        if start > prev_end:
            gap_text = text[prev_end:start]
            if gap_text.strip():
                all_spans.append((prev_end, start, "text"))
        all_spans.append((start, end, comp_type))
        prev_end = end

    # Trailing gap
    if prev_end < len(text) and text[prev_end:].strip():
        all_spans.append((prev_end, len(text), "text"))

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
