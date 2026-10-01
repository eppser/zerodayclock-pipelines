"""The two canonical disclaimers, for the pipeline side.

CLAUDE.md declares these strings NORMATIVE: verbatim wherever the corresponding metric is
shown, never paraphrased. Stored once and imported so a reviewer diffs one file against
the specification instead of hunting for retyped copies a word apart.

DO NOT EDIT THE TEXT. tests/test_disclaimers.py checks it character-for-character against
CLAUDE.md and against the TypeScript copy, and fails if any of the three disagree.
"""

#: Shown wherever a first-observed-exploitation date or a time-to-exploit figure appears.
DELAYED_EXPLOITATION = (
    "For some vulnerabilities, the first publicly documented evidence of exploitation occurs months or years after CVE publication. This date represents observed confirmation\u2014not necessarily the true start of exploitation\u2014and recent cohorts are right-censored."
)

#: Shown wherever a CVE or NVD publication timestamp is used to measure timing.
CVE_NVD_TIMING = (
    "CVE IDs are assigned by CVE Numbering Authorities, not by NVD. CVE reservation-to-publication can take days or weeks, while NVD generally ingests a CVE shortly after public CVE publication. Neither timestamp reliably measures when the vulnerability first became known."
)

DISCLAIMERS = {
    "delayed_exploitation": DELAYED_EXPLOITATION,
    "cve_nvd_timing": CVE_NVD_TIMING,
}
