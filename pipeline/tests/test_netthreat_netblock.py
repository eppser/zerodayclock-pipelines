"""The routing table at /24 grain (0112): runs split where the origin changes and at every /16."""
import gzip
import io

from zdc_netthreat import reference


def _routing(text: str) -> reference.Routing:
    b = io.BytesIO()
    with gzip.GzipFile(fileobj=b, mode="wb") as g:
        g.write(text.encode())
    return reference.Routing(b.getvalue())


def idx(dotted: str) -> int:
    a, b, c = map(int, dotted.split(".")[:3])
    return (a << 16) | (b << 8) | c


def test_a_more_specific_prefix_splits_the_run_it_sits_in():
    runs = _routing("20.0.0.0\t16\t1\n20.0.5.0\t24\t2\n").runs()
    assert runs == [(idx("20.0.0"), idx("20.0.4"), 1, 16, ()), (idx("20.0.5"), idx("20.0.5"), 2, 24, ()), (idx("20.0.6"), idx("20.0.255"), 1, 16, ())]


def test_a_run_never_crosses_a_slash16_and_keeps_its_covering_length():
    runs = _routing("11.0.0.0\t15\t3\n").runs()
    assert runs == [(idx("11.0.0"), idx("11.0.255"), 3, 15, ()), (idx("11.1.0"), idx("11.1.255"), 3, 15, ())]
    assert all((r[0] >> 8) == (r[1] >> 8) for r in runs)


def test_a_moas_prefix_keeps_every_origin_and_scoring_keeps_the_first():
    r = _routing("34.1.0.0\t16\t19527_15169\n")
    assert r.runs() == [(idx("34.1.0"), idx("34.1.255"), 19527, 16, (15169,))]
    assert r.size24[19527] == 256 and 15169 not in r.size24           # the score's sizes are unchanged


def test_a_documentation_slash24_inside_an_ordinary_announcement_is_left_off_the_map():
    runs = _routing("203.0.112.0\t22\t9\n").runs()                 # covers 203.0.113.0/24 (RFC 5737)
    assert sum(x[1] - x[0] + 1 for x in runs) == 3
    assert all(not (x[0] <= idx("203.0.113") <= x[1]) for x in runs)


def test_a_bogon_is_left_off_the_map_but_not_out_of_the_scores():
    r = _routing("100.123.81.0\t24\t45730\n10.0.0.0\t8\t7\n")
    assert r.runs() == []
    assert r.size24[45730] == 1


def test_runs_cover_exactly_the_routed_slash24s_and_nothing_else():
    r = _routing("12.0.0.0\t22\t4\n12.0.8.0\t24\t5\n13.0.0.0\t8\t6\n")
    runs = r.runs()
    assert sum(x[1] - x[0] + 1 for x in runs) == sum(r.size24.values())
    assert sum(x[1] - x[0] + 1 for x in runs if x[2] == 4) == r.size24[4] == 4
    assert len([1 for x in runs if x[2] == 6]) == 256          # a /8 is 256 /16 runs
    assert all(0 <= x[0] <= x[1] < 1 << 24 for x in runs)     # /24 indexes: nothing finer exists
