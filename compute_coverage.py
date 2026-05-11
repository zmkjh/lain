#!/usr/bin/env python3
"""
Coverage analysis for infrastructure-free P2P connectivity across Chinese ISPs.
Computes the exact probability matrix and performs sensitivity analysis.

Rigorous methodology:
- 7 ISP categories with weighted probabilities
- 3 NAT types (Cone, S_ADF, S_APDF) with provable compatibility rules
- 3-tier IPv6 model (no-ipv6 / stack-only / globally-routable)
- Joint probability computation with asymmetric IPv6 initiation
- Monte Carlo sensitivity analysis
"""

import itertools
import random
import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
from enum import Enum, IntEnum

# ============================================================
# §1  Model Definitions
# ============================================================

class NatType(Enum):
    CONE = "Cone"
    S_ADF = "ADF Symmetric"
    S_APDF = "APDF Symmetric"

class IpV6Tier(IntEnum):
    NONE = 0       # No IPv6 stack
    LINK_LOCAL = 1  # fe80:: only, no global unicast
    GLOBAL = 2      # Global prefix assigned
    REACHABLE = 3   # Global + firewall open (inbound allowed)

@dataclass
class IspCategory:
    name: str
    weight: float           # proportion of user population
    nat_type: NatType       # IPv4 NAT behavior
    # IPv6 deployment probabilities (must sum to 1.0)
    ipv6_tier_dist: Dict[IpV6Tier, float] = field(default_factory=dict)
    # For backward compat with simpler model
    ipv6_reachable: float = 0.0  # shorthand: P(tier >= REACHABLE)


# ============================================================
# §2  ISP Data (2025 Q4, multiple sources)
# ============================================================

ISP_CATEGORIES: List[IspCategory] = [
    IspCategory(
        name="A: 移动宽带",
        weight=0.25,
        nat_type=NatType.S_APDF,
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.05,   # rural areas without IPv6 CPE
            IpV6Tier.LINK_LOCAL: 0.15,   # stack online but no prefix assigned
            IpV6Tier.GLOBAL:     0.15,   # prefix assigned, firewall blocks
            IpV6Tier.REACHABLE:  0.65,   # configured for inbound
        },
        ipv6_reachable=0.80  # tier GLOBAL + REACHABLE minus firewall estimate
    ),
    IspCategory(
        name="B: 移动 4G/5G",
        weight=0.20,
        nat_type=NatType.S_ADF,
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.05,
            IpV6Tier.LINK_LOCAL: 0.10,
            IpV6Tier.GLOBAL:     0.55,   # has 2409: prefix but core ACL blocks
            IpV6Tier.REACHABLE:  0.30,
        },
        ipv6_reachable=0.30
    ),
    IspCategory(
        name="C: 电信宽带",
        weight=0.15,
        nat_type=NatType.CONE,
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.01,
            IpV6Tier.LINK_LOCAL: 0.02,
            IpV6Tier.GLOBAL:     0.02,
            IpV6Tier.REACHABLE:  0.95,
        },
        ipv6_reachable=0.95
    ),
    IspCategory(
        name="D: 电信 4G/5G",
        weight=0.12,
        nat_type=NatType.CONE,
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.02,
            IpV6Tier.LINK_LOCAL: 0.03,
            IpV6Tier.GLOBAL:     0.05,
            IpV6Tier.REACHABLE:  0.90,
        },
        ipv6_reachable=0.90
    ),
    IspCategory(
        name="E: 联通宽带",
        weight=0.09,
        nat_type=NatType.CONE,  # conservative: mixed Cone/EDM, treat as Cone
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.05,
            IpV6Tier.LINK_LOCAL: 0.05,
            IpV6Tier.GLOBAL:     0.20,
            IpV6Tier.REACHABLE:  0.70,
        },
        ipv6_reachable=0.70
    ),
    IspCategory(
        name="F: 联通 4G/5G",
        weight=0.08,
        nat_type=NatType.S_ADF,  # conservative: 5G SA blocks inbound
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.05,
            IpV6Tier.LINK_LOCAL: 0.10,
            IpV6Tier.GLOBAL:     0.55,
            IpV6Tier.REACHABLE:  0.30,
        },
        ipv6_reachable=0.30
    ),
    IspCategory(
        name="G: 其他/边缘",
        weight=0.11,
        nat_type=NatType.CONE,
        ipv6_tier_dist={
            IpV6Tier.NONE:       0.10,
            IpV6Tier.LINK_LOCAL: 0.20,
            IpV6Tier.GLOBAL:     0.10,
            IpV6Tier.REACHABLE:  0.60,
        },
        ipv6_reachable=0.60
    ),
]

# Verify weights sum to 1.0
total_weight = sum(c.weight for c in ISP_CATEGORIES)
assert abs(total_weight - 1.0) < 0.001, f"Weights sum to {total_weight}"


# ============================================================
# §3  IPv4 NAT Compatibility Matrix (Theorem 1-5 proofs)
# ============================================================

# compatibility[nat_a][nat_b] = is direct IPv4 connection possible?
NAT_COMPAT: Dict[NatType, Dict[NatType, bool]] = {
    NatType.CONE: {
        NatType.CONE:    True,   # Theorem 1
        NatType.S_ADF:   True,   # Corollary to Theorem 2
        NatType.S_APDF:  True,   # Theorem 2 (asymmetric routing)
    },
    NatType.S_ADF: {
        NatType.CONE:    True,   # symmetric
        NatType.S_ADF:   True,   # Theorem 3
        NatType.S_APDF:  False,  # Theorem 5 — incompatible
    },
    NatType.S_APDF: {
        NatType.CONE:    True,   # symmetric
        NatType.S_ADF:   False,  # Theorem 5 — incompatible
        NatType.S_APDF:  False,  # Theorem 4 — hard boundary
    },
}


# ============================================================
# §4  IPv6 Reachability Model
# ============================================================

def ipv6_direct_possible(tier_a: IpV6Tier, tier_b: IpV6Tier) -> bool:
    """
    IPv6 direct connection is possible if at least one peer has inbound IPv6
    reachable (REACHABLE tier). Asymmetric initiation: the blocked peer can
    initiate, return traffic matches state entry.

    Tiers below REACHABLE:
    - NONE: no IPv6 stack
    - LINK_LOCAL: fe80:: only, not globally routable
    - GLOBAL: has prefix but firewall blocks inbound (cannot RECEIVE,
              but can INITIATE — return traffic works through state)

    Sufficient condition: max(tier_a, tier_b) >= REACHABLE
    OR (GLOBAL on one side + any tier on other): the GLOBAL side can initiate.
    """
    # At least one is REACHABLE (can receive inbound)
    if tier_a == IpV6Tier.REACHABLE or tier_b == IpV6Tier.REACHABLE:
        return True
    # Both have prefix but firewalls block: one initiates, return traffic works
    if tier_a >= IpV6Tier.GLOBAL and tier_b >= IpV6Tier.GLOBAL:
        return True
    return False


# ============================================================
# §5  Joint Coverage Computation
# ============================================================

def compute_exact_coverage(
    categories: List[IspCategory],
    nat_compat: Dict[NatType, Dict[NatType, bool]],
) -> Tuple[float, List[Dict]]:
    """
    Compute exact pair-wise coverage probability.
    Returns (total_probability, detail_rows).
    """
    n = len(categories)
    total_success = 0.0
    total_pairs = 0.0
    details = []

    for i in range(n):
        for j in range(i, n):  # only upper triangle to avoid double-counting
            cat_i = categories[i]
            cat_j = categories[j]

            # Pair probability: w_i * w_j for i=j, 2 * w_i * w_j for i<j
            if i == j:
                pair_prob = cat_i.weight * cat_i.weight
            else:
                pair_prob = 2 * cat_i.weight * cat_j.weight

            # IPv4: is this NAT pair compatible?
            ipv4_ok = nat_compat[cat_i.nat_type][cat_j.nat_type]

            # IPv6: probability that at least one side is reachable
            # P(IPv6 success) = 1 - P(both unreachable for IPv6)
            # Unreachable = not at GLOBAL or REACHABLE tier
            ipv6_fail = 0.0
            for tier_i, prob_i in cat_i.ipv6_tier_dist.items():
                for tier_j, prob_j in cat_j.ipv6_tier_dist.items():
                    if not ipv6_direct_possible(tier_i, tier_j):
                        ipv6_fail += prob_i * prob_j

            ipv6_success = 1.0 - ipv6_fail

            # Combined: success if IPv6 OR IPv4 works
            pair_success = 1.0 - ipv6_fail * (0 if ipv4_ok else 1)
            total_success += pair_prob * pair_success
            total_pairs += pair_prob

            details.append({
                "pair": f"{cat_i.name} × {cat_j.name}",
                "weight": round(pair_prob, 6),
                "nat_compat": ipv4_ok,
                "ipv6_success": round(ipv6_success, 6),
                "pair_success": round(pair_success, 6),
            })

    return total_success, details


def compute_coverage_matrix(
    categories: List[IspCategory],
    nat_compat: Dict[NatType, Dict[NatType, bool]],
) -> List[List[float]]:
    """Compute the 7x7 pair success matrix for Table 4."""
    n = len(categories)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            ipv4_ok = nat_compat[categories[i].nat_type][categories[j].nat_type]
            ipv6_fail = 0.0
            for tier_i, prob_i in categories[i].ipv6_tier_dist.items():
                for tier_j, prob_j in categories[j].ipv6_tier_dist.items():
                    if not ipv6_direct_possible(tier_i, tier_j):
                        ipv6_fail += prob_i * prob_j
            matrix[i][j] = 1.0 - ipv6_fail * (0 if ipv4_ok else 1)
    return matrix


# ============================================================
# §6  Monte Carlo Sensitivity Analysis
# ============================================================

@dataclass
class SensitivityResult:
    name: str
    coverage: float
    param_range: Tuple[float, float]

def monte_carlo_sensitivity(
    categories: List[IspCategory],
    nat_compat: Dict[NatType, Dict[NatType, bool]],
    num_samples: int = 10000,
) -> List[SensitivityResult]:
    """
    Monte Carlo sensitivity: perturb category weights and IPv6 reachability
    rates within plausible ranges, compute coverage distribution.
    """
    import copy

    coverage_samples: List[float] = []
    for _ in range(num_samples):
        cats = copy.deepcopy(categories)

        # Perturb weights with Dirichlet noise
        raw = [max(0.01, c.weight + random.gauss(0, 0.02)) for c in cats]
        total = sum(raw)
        for c, w in zip(cats, raw):
            c.weight = w / total

        # Perturb IPv6 reachability
        for c in cats:
            delta = random.gauss(0, 0.05)  # ±10% 95% CI
            c.ipv6_reachable = max(0.05, min(0.99, c.ipv6_reachable + delta))
            # Rebuild tier distribution
            reach = c.ipv6_reachable
            unreach = 1.0 - reach
            c.ipv6_tier_dist = {
                IpV6Tier.NONE:  unreach * 0.3,
                IpV6Tier.LINK_LOCAL: unreach * 0.5,
                IpV6Tier.GLOBAL: unreach * 0.2,
                IpV6Tier.REACHABLE: reach,
            }

        cov, _ = compute_exact_coverage(cats, nat_compat)
        coverage_samples.append(cov)

    import statistics
    mean_cov = statistics.mean(coverage_samples)
    std_cov = statistics.stdev(coverage_samples)

    return [
        SensitivityResult("Central estimate", mean_cov, (0, 0)),
        SensitivityResult("95% CI low", mean_cov - 1.96 * std_cov, (0, 0)),
        SensitivityResult("95% CI high", mean_cov + 1.96 * std_cov, (0, 0)),
        SensitivityResult("Best case", max(coverage_samples), (0, 0)),
        SensitivityResult("Worst case", min(coverage_samples), (0, 0)),
    ]


# ============================================================
# §7  Layer Decomposition
# ============================================================

def compute_layer_coverage(
    categories: List[IspCategory],
    nat_compat: Dict[NatType, Dict[NatType, bool]],
) -> Dict[str, float]:
    """Compute coverage contribution per layer."""
    # Layer 1: IPv6 direct only
    ipv6_only = 0.0
    both = 0.0
    total_weight = 0.0
    n = len(categories)

    for i in range(n):
        for j in range(i, n):
            ci, cj = categories[i], categories[j]
            w = ci.weight * cj.weight if i == j else 2 * ci.weight * cj.weight
            total_weight += w

            # IPv6 probability
            ipv6_ok_prob = 0.0
            for ti, pi in ci.ipv6_tier_dist.items():
                for tj, pj in cj.ipv6_tier_dist.items():
                    if ipv6_direct_possible(ti, tj):
                        ipv6_ok_prob += pi * pj

            ipv6_only += w * ipv6_ok_prob

            ipv4_ok = nat_compat[ci.nat_type][cj.nat_type]
            both += w * (1.0 - (1.0 - ipv6_ok_prob) * (0 if ipv4_ok else 1))

    return {
        "IPv6 direct": ipv6_only / total_weight,
        "IPv6 + IPv4 STUN": both / total_weight,
        "Remaining (relay)": 1.0 - both / total_weight,
    }


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Lain 覆盖率分析 — 计算引擎")
    print("=" * 70)

    # Exact coverage
    coverage, details = compute_exact_coverage(ISP_CATEGORIES, NAT_COMPAT)
    print(f"\n精确覆盖率: {coverage:.6f} ({coverage*100:.2f}%)")

    # Layer decomposition
    layers = compute_layer_coverage(ISP_CATEGORIES, NAT_COMPAT)
    print(f"\n逐层分解:")
    for name, cov in layers.items():
        print(f"  {name}: {cov*100:.1f}%")

    # Coverage matrix
    matrix = compute_coverage_matrix(ISP_CATEGORIES, NAT_COMPAT)
    print(f"\n7×7 配对成功率矩阵:")
    header = "       " + " ".join(f"{'ABCDEFG'[i]:>6s}" for i in range(7))
    print(header)
    for i in range(7):
        row = f"{'ABCDEFG'[i]:>6s} " + " ".join(f"{matrix[i][j]:5.3f}" for j in range(7))
        print(row)

    # Sensitivity
    print(f"\n蒙特卡洛灵敏度分析 (10,000 次采样):")
    sens = monte_carlo_sensitivity(ISP_CATEGORIES, NAT_COMPAT, num_samples=10000)
    for s in sens:
        print(f"  {s.name}: {s.coverage*100:.2f}%")

    # Export JSON for paper embedding
    result = {
        "exact_coverage": round(coverage, 6),
        "coverage_percent": round(coverage * 100, 2),
        "layers": {k: round(v, 4) for k, v in layers.items()},
        "matrix": [[round(x, 4) for x in row] for row in matrix],
        "monte_carlo": {s.name: round(s.coverage, 6) for s in sens},
    }
    with open("coverage-results.json", "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n结果已导出到 coverage-results.json")
