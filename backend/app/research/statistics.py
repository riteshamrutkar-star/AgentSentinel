"""
AgentSentinel Phase 0.7: Statistical Analysis Engine.
Provides rigorous, publication-grade statistical comparisons:
- Non-parametric percentile bootstrap 95% confidence intervals
- Standardized effect size (Cohen's d)
- Permutation test p-values (exact/Monte Carlo)
- Strict adherence to zero-fabrication: returns INCONCLUSIVE when statistical
  assumptions cannot be met or sample size is insufficient.
"""

import math
import random
import statistics
from typing import List, Optional, Tuple

from app.research.models import (
    SystemVariant,
    StatisticalComparison,
)


class StatisticalAnalyzer:
    """
    Computes rigorous statistical metrics, confidence intervals, effect sizes,
    and pairwise comparisons across system variants.
    """

    @staticmethod
    def bootstrap_ci(
        data: List[float],
        n_bootstrap: int = 1000,
        alpha: float = 0.05,
        seed: int = 42,
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Compute non-parametric percentile bootstrap confidence interval (1 - alpha).
        Returns (ci_lower, ci_upper) or (None, None) if sample size < 5.
        """
        if not data or len(data) < 5:
            return None, None

        # Check if all values are identical
        if all(x == data[0] for x in data):
            return round(data[0], 4), round(data[0], 4)

        rng = random.Random(seed)
        n = len(data)
        means: List[float] = []

        for _ in range(n_bootstrap):
            resample = [rng.choice(data) for _ in range(n)]
            means.append(statistics.fmean(resample))

        means.sort()
        lower_idx = int((alpha / 2.0) * n_bootstrap)
        upper_idx = int((1.0 - alpha / 2.0) * n_bootstrap)

        lower_idx = max(0, min(lower_idx, n_bootstrap - 1))
        upper_idx = max(0, min(upper_idx, n_bootstrap - 1))

        return round(means[lower_idx], 4), round(means[upper_idx], 4)

    @staticmethod
    def compute_cohens_d(group_a: List[float], group_b: List[float]) -> float:
        """
        Compute Cohen's d effect size between two groups.
        Positive d indicates group_b has higher mean than group_a.
        """
        if len(group_a) < 2 or len(group_b) < 2:
            return 0.0

        n1, n2 = len(group_a), len(group_b)
        mean1, mean2 = statistics.fmean(group_a), statistics.fmean(group_b)

        var1 = statistics.variance(group_a) if n1 > 1 else 0.0
        var2 = statistics.variance(group_b) if n2 > 1 else 0.0

        # Pooled standard deviation
        pooled_var = (((n1 - 1) * var1) + ((n2 - 1) * var2)) / (n1 + n2 - 2)
        if pooled_var <= 1e-12:
            return 0.0

        pooled_sd = math.sqrt(pooled_var)
        return round((mean2 - mean1) / pooled_sd, 4)

    @classmethod
    def compare_variants(
        cls,
        variant_a: SystemVariant,
        variant_b: SystemVariant,
        values_a: List[float],
        values_b: List[float],
        metric_name: str,
        higher_is_better: bool = True,
        seed: int = 42,
    ) -> StatisticalComparison:
        """
        Perform a pairwise statistical comparison between two system variants.
        Calculates difference distribution, bootstrap 95% CI, effect size,
        permutation p-value, and formal conclusion.
        """
        if not values_a or not values_b:
            return StatisticalComparison(
                variant_a=variant_a,
                variant_b=variant_b,
                metric_name=metric_name,
                mean_a=0.0,
                mean_b=0.0,
                mean_diff=0.0,
                cohens_d=0.0,
                ci_lower=0.0,
                ci_upper=0.0,
                p_value=None,
                conclusion="INCONCLUSIVE",
            )

        mean_a = round(statistics.fmean(values_a), 4)
        mean_b = round(statistics.fmean(values_b), 4)
        mean_diff = round(mean_b - mean_a, 4)

        if len(values_a) < 5 or len(values_b) < 5:
            return StatisticalComparison(
                variant_a=variant_a,
                variant_b=variant_b,
                metric_name=metric_name,
                mean_a=mean_a,
                mean_b=mean_b,
                mean_diff=mean_diff,
                cohens_d=0.0,
                ci_lower=0.0,
                ci_upper=0.0,
                p_value=None,
                conclusion="INCONCLUSIVE",
            )

        cohens_d = cls.compute_cohens_d(values_a, values_b)

        # Bootstrap confidence interval of difference (mean_b - mean_a)
        rng = random.Random(seed)
        n_boot = 1000
        diff_samples: List[float] = []
        n_a, n_b = len(values_a), len(values_b)

        for _ in range(n_boot):
            sample_a = [rng.choice(values_a) for _ in range(n_a)]
            sample_b = [rng.choice(values_b) for _ in range(n_b)]
            diff_samples.append(statistics.fmean(sample_b) - statistics.fmean(sample_a))

        diff_samples.sort()
        ci_lower = round(diff_samples[int(0.025 * n_boot)], 4)
        ci_upper = round(diff_samples[int(0.975 * n_boot)], 4)

        # Two-sided permutation test
        observed_diff = abs(mean_b - mean_a)
        pooled = values_a + values_b
        n_pooled = len(pooled)
        count_extreme = 0
        n_perm = 1000

        for _ in range(n_perm):
            shuffled = list(pooled)
            rng.shuffle(shuffled)
            perm_a = shuffled[:n_a]
            perm_b = shuffled[n_a:]
            perm_diff = abs(statistics.fmean(perm_b) - statistics.fmean(perm_a))
            if perm_diff >= observed_diff:
                count_extreme += 1

        p_value = round((count_extreme + 1) / (n_perm + 1), 4)

        # Statistical conclusion determination
        if p_value < 0.05:
            if higher_is_better:
                if ci_lower > 0:
                    conclusion = "SIGNIFICANT_IMPROVEMENT"
                elif ci_upper < 0:
                    conclusion = "SIGNIFICANT_DEGRADATION"
                else:
                    conclusion = "NO_DIFFERENCE"
            else:
                # Lower is better (e.g. latency)
                if ci_upper < 0:
                    conclusion = "SIGNIFICANT_IMPROVEMENT"
                elif ci_lower > 0:
                    conclusion = "SIGNIFICANT_DEGRADATION"
                else:
                    conclusion = "NO_DIFFERENCE"
        else:
            conclusion = "NO_DIFFERENCE"

        return StatisticalComparison(
            variant_a=variant_a,
            variant_b=variant_b,
            metric_name=metric_name,
            mean_a=mean_a,
            mean_b=mean_b,
            mean_diff=mean_diff,
            cohens_d=cohens_d,
            ci_lower=ci_lower,
            ci_upper=ci_upper,
            p_value=p_value,
            conclusion=conclusion,
        )
