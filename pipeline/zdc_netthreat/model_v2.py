"""network_threat_score v2: two sides, one latent intensity per network and side.

For every routed network i and every feed f on a side:

    n_if ~ NegBin(mean = E_if * exp(alpha_f + theta_i), size phi_f)
    E_if = s24_i * T_f / S          (the network's fair share: its routed /24s times the feed's
                                     total, over the routed /24s of the whole internet)
    theta_i ~ N(mu0, tau^2)         (one prior for every network; a silent network is a zero)

Fitted by EM with the latent on a grid, over EVERY routed network: silent networks of the same
size share a likelihood and are collapsed into one weighted row, which is what makes 79,000
networks fit in seconds. Published per network: theta's posterior mode and 10th percentile
relative to the routed-weighted internet average (so 1.0 = an average routed /24), the
posterior SD, expected bad /24s, the share of observed appearances the largest feed holds, and
each feed's exact push on the mode (they sum to mode - mu0).

Two sides because they are uncorrelated (Spearman -0.06 on 2026-10-05): ATTACK = feeds that
see the attacker (crowdsec, dshield, blocklist_de, cins, vulncheck); HOST = feeds that see what
is hosted (threatfox, urlhaus, phishing_db, shodan). The caller fits each side separately.

numpy only. gammaln and digamma are implemented here (Lanczos / asymptotic) so the pipeline
needs no scipy. The M-step is a few damped Newton sweeps per feed on (alpha, log phi): EM
needs only an improvement, not the exact maximiser. Everything is deterministic.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

import numpy as np

#: Shodan is NOT in the hosted side yet: it reports host counts with no /24 detail and its
#: facet cap makes coverage swing between fetches (1,149 vs 2,489 networks on the same week),
#: which moved the hosting ranking by Spearman 0.56-0.75 and made every gated week provisional.
#: It returns once the pipeline stores Shodan /24s and coverage has held for several weeks
#: (review round 2, 2026-10-14). Its tags stay on the page as a source badge.
SIDES: dict[str, tuple[str, ...]] = {
    "attack": ("crowdsec", "dshield", "blocklist_de", "cins", "vulncheck"),
    "host": ("threatfox", "urlhaus", "phishing_db"),
}
#: Listing gate: intensity floor at least GATE_X times the internet average AND at least
#: GATE_MASS expected bad /24s on that side. Hysteresis: a network stays listed until its
#: expected bad /24s fall below GATE_MASS_STAY (spec 2026-10-13, section 2).
GATE_X, GATE_MASS, GATE_MASS_STAY = 10.0, 50.0, 35.0
#: 69 points, step 0.25 on the log scale: the 10th percentile is interpolated between points,
#: and a coarser grid (24 points) moved the hosting side's internet average by 0.35 on the log
#: scale against the 86-point research fit. Measured 2026-10-14.
GRID = np.linspace(-9.0, 9.0, 73)
LOWER_Q = 0.10
#: Real hosting-side fits take ~370 iterations (the log-likelihood increment decays by ~0.96 per
#: iteration); a cap of 400 blocked weeks for no statistical reason. 1,000 costs ~40 s more at worst.
MAX_ITERS, TOL, PARAM_TOL = 1000, 1e-2, 1e-4
#: Wall-clock cap per side. Measured on 2026-10-05 data: 0.27 s per iteration on the attack side
#: locally (44 s for 161 iterations), 25 s for the hosting side; a 2-vCPU runner is about twice
#: slower, so even 1,000 iterations stay under ten minutes. The cap is a backstop for the job budget. A fit
#: that hits the cap returns converged = False, which marks the week provisional and blocks it
#: (v2_converged) rather than letting the runner kill the job after collection.
MAX_SECONDS = 900.0


# ------------------------------------------------------------------------------ special functions
_LANCZOS_G = 7.0
_LANCZOS_C = np.array([
    0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
    -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6,
    1.5056327351493116e-7])


def gammaln(x):
    """log Gamma(x) for x > 0, vectorised. Lanczos (g=7, n=9): |error| < 1e-13 for x >= 1;
    x in (0, 1) uses lgamma(x) = lgamma(x + 1) - log(x)."""
    x = np.asarray(x, dtype=float)
    small = x < 1.0
    xs = np.where(small, x + 1.0, x)
    z = xs - 1.0
    s = np.full_like(z, _LANCZOS_C[0])
    for i, c in enumerate(_LANCZOS_C[1:], start=1):
        s = s + c / (z + i)
    t = z + _LANCZOS_G + 0.5
    out = 0.5 * math.log(2 * math.pi) + (z + 0.5) * np.log(t) - t + np.log(s)
    return np.where(small, out - np.log(np.where(small, x, 1.0)), out)


def digamma(x):
    """psi(x) for x > 0, vectorised: shift to x >= 6 by recurrence, then the asymptotic series."""
    x = np.asarray(x, dtype=float)
    acc = np.zeros_like(x)
    xx = x.copy()
    for _ in range(6):
        m = xx < 6.0
        acc = np.where(m, acc - 1.0 / xx, acc)
        xx = np.where(m, xx + 1.0, xx)
    inv = 1.0 / xx
    inv2 = inv * inv
    return acc + np.log(xx) - 0.5 * inv - inv2 * (1 / 12 - inv2 * (1 / 120 - inv2 * (1 / 252 - inv2 * (1 / 240 - inv2 / 132))))


def nb_logpmf(n, mu, phi):
    mu = np.maximum(mu, 1e-12)
    return (gammaln(n + phi) - gammaln(phi) - gammaln(n + 1) + phi * np.log(phi) - phi * np.log(phi + mu)
            + n * np.log(mu) - n * np.log(phi + mu))


# ------------------------------------------------------------------------------ inputs and outputs
@dataclass
class SideInput:
    """One side's counts over every routed network.

    asns:  every routed ASN (int array, length A)
    s24:   routed /24s per ASN (float array, length A), all > 0
    feeds: feed ids present on this side, in order
    counts: A x F occupied /24s (Shodan: hosts, capped at s24 by the caller)
    totals: per feed, the feed's total over ALL networks (the fair-share numerator)
    routed_total: routed /24s of the whole internet (the fair-share denominator)
    union_24s: distinct bad /24s across this side's IP feeds, summed over networks, or None
    ip_feeds: per feed, whether it reports addresses (True) or only counts (False: Shodan). The
              de-duplication factor is measured over the IP feeds and applied to their share of
              the expected mass only.
    """
    asns: np.ndarray
    s24: np.ndarray
    feeds: list[str]
    counts: np.ndarray
    totals: np.ndarray
    routed_total: float
    union_24s: float | None = None
    ip_feeds: tuple[bool, ...] | None = None
    #: Use this de-duplication factor instead of measuring one (a week without a per-side union).
    rho_fixed: float | None = None


@dataclass
class SideFit:
    feeds: list[str]
    alpha: np.ndarray
    phi: np.ndarray
    mu0: float
    tau: float
    ref: float                  # log routed-weighted mean intensity: the internet average
    rho: float                  # de-duplication across the side's feeds
    kappa: float                # sum_f rate_f e^alpha_f: summed appearances per /24 at intensity 1
    loglik: float
    iterations: int
    converged: bool
    seconds: float
    # per ASN (length A), all relative to ref where it is an intensity
    theta: np.ndarray           # posterior mode, log scale, minus ref
    lo: np.ndarray              # 10th percentile, log scale, minus ref
    se: np.ndarray              # posterior SD, log scale
    e_exp: np.ndarray           # E[e^theta], absolute
    mass: np.ndarray            # expected distinct bad /24s
    obs: np.ndarray             # summed observed appearances
    top_share: np.ndarray       # largest feed's share of obs (nan when obs == 0)
    contrib: np.ndarray         # A x F push on the mode; rows sum to theta_abs - mu0
    asns: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    counts: np.ndarray = field(default_factory=lambda: np.zeros((0, 0)))   # A x F, capped at s24
    totals: np.ndarray = field(default_factory=lambda: np.zeros(0))
    notes: dict = field(default_factory=dict)


def _collapse(counts: np.ndarray, s24: np.ndarray):
    """Silent networks of equal size share a likelihood: collapse them into weighted rows.
    Returns (row index per ASN, unique counts, unique s24, weights)."""
    silent = counts.sum(1) == 0
    key = np.where(silent, s24, -np.arange(1, len(s24) + 1, dtype=float))
    uniq, inv, w = np.unique(key, return_inverse=True, return_counts=True)
    first = np.zeros(len(uniq), int)
    first[inv] = np.arange(len(inv))
    return inv, counts[first], s24[first], w.astype(float)


def _mstep_feed(n, E, Wt, alpha, phi, grid, sweeps=3):
    """Damped Newton on alpha and on log phi for one feed, given posterior weights Wt (rows x grid).
    Each step is accepted only if the expected log-likelihood does not fall."""
    th = grid[None, :]

    def q(a, p):
        mu = E * np.exp(a + th)
        return float((Wt * nb_logpmf(n, mu, p)).sum())

    cur = q(alpha, phi)
    for _ in range(sweeps):
        mu = E * np.exp(alpha + th)
        r = phi / (phi + mu)
        g = float((Wt * (n - mu) * r).sum())
        h = float(-(Wt * mu * phi * (phi + n) / (phi + mu) ** 2).sum())
        step = np.clip(-g / h if h < 0 else 0.0, -1.0, 1.0)
        for _ in range(8):                       # backtracking
            cand = q(alpha + step, phi)
            if cand >= cur - 1e-9:
                alpha, cur = alpha + step, cand
                break
            step *= 0.5
        mu = E * np.exp(alpha + th)

        def dq_dlogphi(p):
            return float(p * (Wt * (digamma(n + p) - digamma(p) + math.log(p) - np.log(p + mu)
                                    + 1 - (n + p) / (p + mu))).sum())
        lp = math.log(phi)
        dg = dq_dlogphi(phi)
        # Newton in log phi with a finite-difference second derivative; bounded and backtracked
        eps = 1e-3
        h2 = (dq_dlogphi(math.exp(lp + eps)) - dq_dlogphi(math.exp(lp - eps))) / (2 * eps)
        step = float(np.clip(-dg / h2 if h2 < 0 else math.copysign(0.25, dg), -1.0, 1.0))
        for _ in range(8):
            cand = q(alpha, math.exp(lp + step))
            if cand >= cur - 1e-9:
                phi, cur = math.exp(lp + step), cand
                break
            step *= 0.5
        phi = float(min(max(phi, 1e-3), 1e3))
    return alpha, phi, cur


def fit_side(inp: SideInput, grid: np.ndarray = GRID, max_iters: int = MAX_ITERS, tol: float = TOL,
             max_seconds: float = MAX_SECONDS) -> SideFit:
    t0 = time.monotonic()
    feeds = list(inp.feeds)
    A, F = inp.counts.shape
    s24 = inp.s24.astype(float)
    if A == 0 or F == 0 or not np.all(s24 > 0):
        raise ValueError("fit_side needs at least one network, one feed, and positive sizes")
    rates = inp.totals.astype(float) / float(inp.routed_total)
    counts = np.minimum(inp.counts.astype(float), s24[:, None])        # nothing can occupy more /24s than it routes
    inv, Nu, s24u, w = _collapse(counts, s24)
    Eu = s24u[:, None] * rates[None, :]
    g = len(grid)
    alpha = np.zeros(F)
    phi = np.ones(F)
    mu0, tau2 = -1.0, 2.0
    ll_old, it, converged = -np.inf, 0, False
    prev_params = None
    trace: list[tuple[float, float, float]] = []
    TH = grid[None, :]
    for it in range(1, max_iters + 1):
        L = np.zeros((len(Nu), g))
        for f in range(F):
            L += nb_logpmf(Nu[:, f, None], Eu[:, f, None] * np.exp(alpha[f] + TH), phi[f])
        LP = L - 0.5 * (TH - mu0) ** 2 / tau2
        mx = LP.max(1, keepdims=True)
        W = np.exp(LP - mx)
        Z = W.sum(1, keepdims=True)
        W /= Z
        ll = float((w * (mx[:, 0] + np.log(Z[:, 0]))).sum())
        Wt = W * w[:, None]
        for f in range(F):
            alpha[f], phi[f], _ = _mstep_feed(Nu[:, f, None], Eu[:, f, None], Wt, alpha[f], phi[f], grid)
        pm = W @ grid
        pv = W @ (grid ** 2) - pm ** 2
        mu0 = float((w * pm).sum() / w.sum())
        tau2 = float(max((w * (pv + (pm - mu0) ** 2)).sum() / w.sum(), 1e-4))
        # Identifiability: only alpha_f + theta_i enters the likelihood, so the prior mean and
        # every alpha can drift together along a ridge. Pin the routed-weighted mean intensity
        # to 1 (ref = 0): shift theta's prior down by the current ref and every alpha up by it.
        e_exp_u = W @ np.exp(grid)
        shift = math.log(float((s24u * w * e_exp_u).sum() / (s24u * w).sum()))
        mu0 -= shift
        alpha += shift
        trace.append((ll, mu0, math.sqrt(tau2)))
        # Stop only when the log-likelihood AND every parameter have settled: a slow ridge can
        # move the log-likelihood by less than tol per iteration while alpha still drifts.
        params = np.concatenate([alpha, np.log(phi), [mu0, math.sqrt(tau2)]])
        settled = prev_params is not None and float(np.abs(params - prev_params).max()) < PARAM_TOL
        if abs(ll - ll_old) < tol and settled:
            converged = True
            break
        ll_old, prev_params = ll, params
        if time.monotonic() - t0 > max_seconds:
            break                        # converged stays False: the caller marks the side provisional
    # final posterior on the unique rows
    L = np.zeros((len(Nu), g))
    for f in range(F):
        L += nb_logpmf(Nu[:, f, None], Eu[:, f, None] * np.exp(alpha[f] + TH), phi[f])
    LP = L - 0.5 * (TH - mu0) ** 2 / tau2
    W = np.exp(LP - LP.max(1, keepdims=True))
    W /= W.sum(1, keepdims=True)
    pm = W @ grid
    psd = np.sqrt(np.maximum(W @ (grid ** 2) - pm ** 2, 0.0))
    e_exp = W @ np.exp(grid)
    cdf = np.cumsum(W, 1)
    rows = np.arange(len(Nu))
    k = np.minimum((cdf < LOWER_Q).sum(1), g - 1)
    c_hi = cdf[rows, k]
    c_lo = np.where(k > 0, cdf[rows, np.maximum(k - 1, 0)], 0.0)
    frac = np.clip((LOWER_Q - c_lo) / np.maximum(c_hi - c_lo, 1e-12), 0, 1)
    step = grid[1] - grid[0]
    # Each grid point carries the posterior mass of the cell CENTRED on it, so the quantile sits
    # half a step above the plain cumulative-sum reading (measured: -12% bias without it).
    lo = np.where(k > 0, grid[np.maximum(k - 1, 0)], grid[0] - step) + frac * step + step / 2
    lo = np.clip(lo, grid[0], grid[-1])
    # mode: grid argmax, then Newton
    th = grid[LP.argmax(1)].copy()
    for _ in range(40):
        mu = Eu * np.exp(alpha[None, :] + th[:, None])
        r = phi[None, :] / (phi[None, :] + mu)
        grad = ((Nu - mu) * r).sum(1) - (th - mu0) / tau2
        hess = -(mu * phi[None, :] * (phi[None, :] + Nu) / (phi[None, :] + mu) ** 2).sum(1) - 1 / tau2
        d = np.clip(grad / hess, -1, 1)
        th -= d
        if np.abs(d).max() < 1e-9:
            break
    mu = Eu * np.exp(alpha[None, :] + th[:, None])
    contrib_u = tau2 * (Nu - mu) * phi[None, :] / (phi[None, :] + mu)
    # back to every ASN
    ref = math.log(float((s24 * e_exp[inv]).sum() / s24.sum()))
    obs = counts.sum(1)
    top = np.where(obs > 0, counts.max(1) / np.maximum(obs, 1e-12), np.nan)
    # De-duplication is measured over the feeds that report addresses (a /24 seen by three IP
    # feeds is one /24 in the union) and applied to their share of the mass only; a count-only
    # feed (Shodan) is already in /24 units and enters undiscounted.
    ip = np.array(inp.ip_feeds if inp.ip_feeds is not None else [True] * F, dtype=bool)
    ip_sum = float(counts[:, ip].sum())
    if inp.rho_fixed is not None:
        rho = float(inp.rho_fixed)
    else:
        rho = float(inp.union_24s / max(1.0, ip_sum)) if (inp.union_24s is not None and ip.any() and ip_sum > 0) else 1.0
    rho = min(max(rho, 0.05), 1.0)
    kappa_ip = float((rates[ip] * np.exp(alpha[ip])).sum())
    kappa_other = float((rates[~ip] * np.exp(alpha[~ip])).sum())
    kappa = rho * kappa_ip + kappa_other
    mass = s24 * kappa * e_exp[inv]
    return SideFit(feeds=feeds, alpha=alpha, phi=phi, mu0=mu0, tau=math.sqrt(tau2), ref=ref, rho=rho, kappa=kappa,
                   loglik=ll, iterations=it, converged=converged, seconds=time.monotonic() - t0,
                   theta=th[inv] - ref, lo=lo[inv] - ref, se=psd[inv], e_exp=e_exp[inv], mass=mass,
                   obs=obs, top_share=top, contrib=contrib_u[inv], asns=np.asarray(inp.asns), counts=counts, totals=np.asarray(inp.totals, float),
                   notes={"unique_rows": int(len(Nu)), "networks": int(A), "grid": int(g),
                          "time_capped": (not converged) and (time.monotonic() - t0 > max_seconds),
                          "rho_denominator_ip_24s": ip_sum, "rho_union_24s": inp.union_24s,
                          "trace": [(round(a, 2), round(b, 4), round(c, 4)) for a, b, c in trace[::10] + trace[-1:]]})


# ------------------------------------------------------------------------------ summaries
def listed(lo_x: float, mass: float, was_listed: bool = False) -> bool:
    """The list gate with hysteresis: enter at (>= 10x, >= 50), leave only under 35 bad /24s
    or under 10x. lo_x is the floor as a multiple of the internet average."""
    if lo_x < GATE_X:
        return False
    return mass >= (GATE_MASS_STAY if was_listed else GATE_MASS)


def band(attack_lo_x: float | None, host_lo_x: float | None, attack_listed: bool, host_listed: bool) -> int:
    if attack_listed or host_listed:
        return 2
    return 1 if max(attack_lo_x or 0.0, host_lo_x or 0.0) >= GATE_X else 0


def _ranks(x: np.ndarray) -> np.ndarray:
    """Average ranks (ties share), 1-based."""
    x = np.asarray(x, float)
    order = np.argsort(x, kind="mergesort")
    r = np.empty(len(x), float)
    r[order] = np.arange(1, len(x) + 1)
    # ties: average
    sx = x[order]
    i = 0
    while i < len(sx):
        j = i
        while j + 1 < len(sx) and sx[j + 1] == sx[i]:
            j += 1
        if j > i:
            r[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return r


def auc(y: np.ndarray, score: np.ndarray) -> float | None:
    """Area under the ROC curve by the rank-sum identity; None without both classes."""
    y = np.asarray(y, bool)
    n1, n0 = int(y.sum()), int((~y).sum())
    if n1 == 0 or n0 == 0:
        return None
    r = _ranks(np.asarray(score, float))
    return float((r[y].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def spearman(a: np.ndarray, b: np.ndarray) -> float | None:
    if len(a) < 3:
        return None
    ra, rb = _ranks(a), _ranks(b)
    ra -= ra.mean(); rb -= rb.mean()
    d = math.sqrt(float((ra ** 2).sum() * (rb ** 2).sum()))
    return float((ra * rb).sum() / d) if d > 0 else None


def gini(x: np.ndarray) -> float:
    x = np.sort(np.asarray(x, float))
    n = len(x)
    if n == 0 or x.sum() <= 0:
        return 0.0
    cum = np.cumsum(x)
    return float((n + 1 - 2 * (cum / cum[-1]).sum()) / n)


def type_reference(asns: np.ndarray, s24: np.ndarray, theta_rel: np.ndarray, types: dict[int, str]) -> dict[str, float]:
    """Routed-weighted mean of the best-estimate intensity per network type (relative to the internet
    average), for 'x own type'. Networks without a known type are left out of every reference."""
    acc: dict[str, list[float]] = {}
    for a, s, t in zip(asns.tolist(), s24.tolist(), theta_rel.tolist()):
        ty = types.get(a)
        if ty:
            acc.setdefault(ty, [0.0, 0.0])
            acc[ty][0] += s * math.exp(t)
            acc[ty][1] += s
    return {ty: v[0] / v[1] for ty, v in acc.items() if v[1] > 0}
