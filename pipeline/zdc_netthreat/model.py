"""The network threat score, as pure functions. No I/O, no clock, no randomness.

THE QUESTION. For one source and one network: is the network's count of occupied /24s
larger than its routed address space predicts, by enough to call it, given that ~3,000
networks are tested against ten feeds at once?

1. Expected count   E_i = routed_24s_i * (sum of counts / sum of routed /24s), per feed.
2. Excess           RR_i ~ Gamma(1, 1) a priori (mean 1: a network is average until shown
                    otherwise). With n_i ~ Poisson(RR_i * E_i), the posterior is
                    Gamma(1 + n_i, 1 + E_i). Reported: mean, 90% interval, P(RR_i >= 3).
                    With shape 1 + n_i an integer, P(RR >= T) = P(Poisson(T(1+E)) <= n),
                    so no special-function library is needed.
3. Above threshold  Bayesian false-discovery control across every (network, feed) pair
                    with n >= 1: sort by P(RR >= 3) and keep the largest prefix whose mean
                    (1 - p) stays at or under 5%, then require n >= MIN_COUNT.
4. Fusion           A two-class latent-class model over binary evidence groups, fitted by
                    EM, estimating each group's hit rate and false-flag rate from how the
                    groups agree. The score is each network's posterior probability of the
                    "flagged together" class.

Why /24s and not IPs: one customer often holds many neighbouring addresses, so IPs
are not independent events; counting occupied /24s removes most of that clustering.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

PRIOR_SHAPE = 1.0
PRIOR_RATE = 1.0
THRESHOLD = 3.0
BFDR = 0.05
MIN_COUNT = 3
SENSOR_QUORUM = 2
LCA_ITERATIONS = 400


def poisson_cdf(k: int, lam: float) -> float:
    """P(X <= k) for X ~ Poisson(lam), summed in log space so large lam cannot underflow
    the first term to zero and silently return 0."""
    if k < 0:
        return 0.0
    if lam <= 0:
        return 1.0
    log_term = -lam          # log P(X = 0)
    log_sum = log_term
    for i in range(1, k + 1):
        log_term += math.log(lam) - math.log(i)
        hi, lo = max(log_sum, log_term), min(log_sum, log_term)
        log_sum = hi + math.log1p(math.exp(lo - hi))
    return min(1.0, math.exp(log_sum))


def p_excess(n: int, expected: float, threshold: float = THRESHOLD) -> float:
    """P(RR >= threshold | n), posterior Gamma(1 + n, 1 + E). Valid for PRIOR_SHAPE = 1."""
    return poisson_cdf(n, threshold * (PRIOR_RATE + expected))


def gamma_quantile(q: float, shape_int: int, rate: float) -> float:
    """Quantile of Gamma(shape_int, rate) for an integer shape, by bisection on the
    Poisson identity P(G <= x) = 1 - P(Poisson(rate x) <= shape - 1)."""
    lo, hi = 0.0, max(1.0, (shape_int + 10 * math.sqrt(shape_int) + 10) / rate)
    for _ in range(200):
        mid = (lo + hi) / 2
        cdf = 1.0 - poisson_cdf(shape_int - 1, rate * mid)
        if cdf < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


@dataclass(frozen=True)
class Excess:
    n: int
    expected: float
    mean: float
    lo90: float
    hi90: float
    p: float


def excess(n: int, expected: float) -> Excess:
    shape, rate = int(PRIOR_SHAPE) + n, PRIOR_RATE + expected
    return Excess(n, expected, shape / rate, gamma_quantile(0.05, shape, rate),
                  gamma_quantile(0.95, shape, rate), p_excess(n, expected))


def score_feed(counts: dict[int, int], routed: dict[int, int], total_routed: int) -> dict[int, Excess]:
    """Per network excess for one feed. The rate is the feed's total over the WHOLE
    internet's routed /24s (`total_routed`), not over the networks that happen to appear.
    Networks with no routed space are skipped: they cannot have an expectation, and an
    infinite excess is not a measurement."""
    total_n = sum(counts.values())
    total_24 = total_routed
    if total_n == 0 or total_24 == 0:
        return {}
    rate = total_n / total_24
    return {a: excess(n, routed[a] * rate) for a, n in counts.items() if routed.get(a, 0) > 0}


def bfdr_select(pairs: list[tuple[float, object]], level: float = BFDR) -> tuple[set, float]:
    """Bayesian FDR: the largest set of highest-p pairs whose mean (1 - p) <= level.
    Returns (selected keys, the smallest p admitted; 1.0 when nothing is admitted)."""
    ranked = sorted(pairs, key=lambda x: -x[0])
    cum, keep = 0.0, 0
    for i, (p, _) in enumerate(ranked, 1):
        cum += 1.0 - p
        if cum / i <= level:
            keep = i
    chosen = ranked[:keep]
    return {k for _, k in chosen}, (chosen[-1][0] if chosen else 1.0)


@dataclass
class LcaFit:
    groups: list[str]
    hit_rate: list[float]
    false_flag_rate: list[float]
    prevalence: float
    posterior: list[float]


def lca(rows: list[list[int]], groups: list[str], iterations: int = LCA_ITERATIONS) -> LcaFit:
    """Two-class latent-class model, conditional independence given class, fitted by EM
    from a fixed start (deterministic). Class 1 is the one with the higher hit rates."""
    m, n = len(groups), len(rows)
    if n == 0 or m == 0:
        return LcaFit(groups, [0.0] * m, [0.0] * m, 0.0, [0.0] * n)
    pi, se, fp = 0.1, [0.6] * m, [0.05] * m
    post = [0.0] * n
    clamp = lambda v, lo, hi: min(hi, max(lo, v))   # noqa: E731
    for _ in range(iterations):
        s1 = 0.0
        a1, a0 = [0.0] * m, [0.0] * m
        for i, x in enumerate(rows):
            l1, l0 = pi, 1.0 - pi
            for j in range(m):
                l1 *= se[j] if x[j] else 1.0 - se[j]
                l0 *= fp[j] if x[j] else 1.0 - fp[j]
            r = l1 / (l1 + l0) if l1 + l0 > 0 else 0.0
            post[i] = r
            s1 += r
            for j in range(m):
                if x[j]:
                    a1[j] += r
                    a0[j] += 1.0 - r
        s0 = n - s1
        pi = clamp(s1 / n, 1e-6, 1 - 1e-6)
        se = [clamp(a1[j] / s1 if s1 else 0.0, 1e-3, 1 - 1e-3) for j in range(m)]
        fp = [clamp(a0[j] / s0 if s0 else 0.0, 1e-4, 1 - 1e-3) for j in range(m)]
    return LcaFit(groups, se, fp, pi, post)


def sensor_group(flags: dict[str, bool], sensors: list[str], quorum: int = SENSOR_QUORUM) -> bool:
    """The four sensor networks see the same scanners, so one evidence group: observed
    when at least `quorum` of them agree (or any one, if fewer than `quorum` are active)."""
    active = [s for s in sensors if s in flags]
    hits = sum(1 for s in active if flags[s])
    return hits >= (quorum if len(active) >= quorum else 1)


def cloudflare_rule(waf12, rep12, waf52, rep52, ratio: float = 2.0) -> bool:
    """Cloudflare observes a network only when customers' WAF blocks AND Cloudflare's own
    IP-reputation blocks are both >= `ratio` x its share of requests, in both windows.
    Each argument is (value, bound) with bound '' (measured), 'lo' (traffic below the
    ranking: a lower bound) or 'hi' (blocks below the ranking: an upper bound, never enough)."""
    def ok(x):
        return x is not None and x[1] != "hi" and x[0] >= ratio
    return all(ok(x) for x in (waf12, rep12, waf52, rep52))
