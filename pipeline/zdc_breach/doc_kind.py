"""Is this article a new breach, or news ABOUT an old one? Decided by rule, before anything is filed.

THE DEFECT (dates audit, 2026-10-21). A lawsuit, settlement, fine, sentencing or anniversary piece about an
old breach was filed like a first report: the resolver, given no stated breach date, looked for an incident of
the same organisation within 90 days of the ARTICLE's date, found none, and created a new incident dated the
day the article ran. Capital One's 2019 breach was listed as a 2025 breach twice (an appeals ruling and a
re-sentencing); 10 of a 40-row sample of press-only rows were wrong (25%, CI 14-40%), every one a follow-up.

THE RULE. A follow-up is ATTACH-ONLY (run.file_output): its claims may join an existing incident of the same
organisation; it never creates an incident and never moves a first-public date. One that matches nothing is
recorded privately in breach_core.press_review and is not public.

DECIDED FROM THE TITLE AND THE EXTRACTOR'S OUTPUT, deterministically, so the decision is reproducible from
the stored document and extraction alone - never a second model call. The extractor's schema has
is_incident_report and nothing about the document's kind; adding a field would change the prompt and its hash,
which is the extractor version every activated field is keyed on. So the kind is derived here:
- not is_incident_report                          -> 'not_incident' (nothing is filed, as before);
- the title carries follow-up vocabulary          -> 'follow_up';
- otherwise                                       -> 'incident_report'.

AN OLD YEAR IS NOT A FOLLOW-UP. "Premier Health Partners Announces July 2023 Data Breach" (2025) is a late
FIRST notice: its date is the first public date, and the audit judged such rows correct (Communications Data
Group, Woodfords Family Services). An old year instead makes the resolver look for the incident of that year
first (fix 2, resolve_incident's coarse match), which links the notice to the breach when one exists.

THE VOCABULARY IS CONSERVATIVE AND READ FROM THE TITLE ONLY. A body nearly always mentions a lawsuit or a
regulator somewhere ("may face class actions"), so body text would turn first reports into follow-ups. Words
that also describe a new breach ("investigation", "charges" as in fees, "fine" as in fine-tuned) are only
matched in an unambiguous phrase; likewise "court", "judge" and "prison", because a court or a prison can be
the breached organisation ("Superior Court hit by ransomware"). Measured on the audit's 40-row sample: all 10
wrong rows caught; of the 30 correct rows 2 carry follow-up titles (an arrest a week after an attack, and a
settlement whose row was right only because another source dated it) - ADR 0006, 2026-10-21 night.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Each alternative names one kind of follow-up; the matched group is recorded as the reason.
FOLLOW_UP_TITLE = re.compile(r"""(?ix)
    (?P<litigation>\b(?:settle[sd]?|settlement|settling|lawsuits?|class[- ]actions?|litigation|sues|sued|suing)\b
                  |\b(?:appeals|federal|district|supreme|high|circuit)\s+court\b|\bcourt\s+of\s+appeals\b|\bin\s+court\b
                  |\bcourt\s+(?:rules|ruled|ruling|approves|approved|orders|ordered|reimposes|dismiss\w*|grants|granted|decision)\b
                  |\bjudge\s+(?:rules|ruled|orders|ordered|approves|approved|dismiss\w*|tosses|blocks|grants|denies|reimposes)\b
                  |\bjury\b|\bverdict\b|\bon\s+appeal\b|\bappeal(?:s|ed)?\s+(?:the\s+|a\s+|his\s+|her\s+)?(?:ruling|sentence|verdict|decision|conviction)\b)
  | (?P<penalty>\bfined\b|\bfines?\s+(?:of\s+)?[$£€]|\bpenalt(?:y|ies)\b|resolution\s+agreement|consent\s+(?:order|decree)
                  |\bagrees?\s+to\s+pay\b|\bto\s+pay\s+[$£€]|\bOCR\b.{0,40}\b(?:settle\w*|resolution|investigation|fine|penalt\w*)\b
                  |\bHIPAA\s+(?:settlement|penalty|fine|enforcement)\b|\benforcement\s+action\b)
  | (?P<criminal>\bsentenc(?:e|ed|es|ing)\b|\bresentenc\w*|\bplead(?:s|ed)?\s+guilty\b|\bpled\s+guilty\b|\bguilty\s+plea\b
                  |\bconvicted\b|\bconviction\b|\bindict(?:ed|ment)\b|\bextradit\w*|\barrest(?:ed|s)?\b
                  |\b(?:in|to)\s+prison\b|\bjail(?:ed|\s+time|\s+term)\b)
  | (?P<retrospective>\banniversary\b|\byears?\s+(?:after|later|on)\b|\bone\s+year\s+on\b|\bretrospective\b|\blooks?\s+back\b
                  |\blessons\s+(?:from|of)\b|\b(?:(?:a|one|two|three|\d+)[- ])?years?[- ]old\s+(?:data\s+)?(?:breach|hack|attack|cyberattack|incident)\b)
  | (?P<renotice>\bre-?notif\w*|\bnew\s+notice\b|\bupdated\s+(?:breach\s+)?notice\b
                  |\b(?:victim|breach|affected)\s+(?:count|toll|tally|total)\s+(?:rises|grows|climbs|increases|jumps)\b)
""")



@dataclass(frozen=True)
class DocKind:
    kind: str                 # 'incident_report' | 'follow_up' | 'not_incident'
    reason: str | None = None  # which vocabulary group decided a follow-up

    @property
    def follow_up(self) -> bool:
        return self.kind == "follow_up"


def classify(title: str | None, output: dict | None) -> DocKind:
    """The document's kind from its title and the extractor's output (see the module docstring)."""
    if not isinstance(output, dict) or not output.get("is_incident_report"):
        return DocKind("not_incident")
    t = " ".join((title or "").split())
    m = FOLLOW_UP_TITLE.search(t)
    if m:
        return DocKind("follow_up", next(k for k, v in m.groupdict().items() if v))
    return DocKind("incident_report")
