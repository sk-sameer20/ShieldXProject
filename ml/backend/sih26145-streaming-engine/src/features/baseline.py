import math
from typing import Dict, Any, Optional


class WelfordAccumulator:
    """
    Implements Welford's algorithm for computing running mean and variance in O(1) space/time.
    """
    def __init__(self):
        self.count: int = 0
        self.mean: float = 0.0
        self.M2: float = 0.0

    def update(self, x: float) -> None:
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        stdev = self.stddev
        if stdev < 1e-6:
            return 0.0
        return (x - self.mean) / stdev


class HostBaseline:
    """
    Maintains per-host baseline statistics with protection against baseline contamination during attacks.
    """

    def __init__(self, warmup_samples: int = 5):
        self.warmup_samples = warmup_samples
        # host_ip -> metric_name -> WelfordAccumulator
        self.metrics: Dict[str, Dict[str, WelfordAccumulator]] = {}
        # host_ip -> is_frozen (bool)
        self.frozen_hosts: Dict[str, bool] = {}

    def is_frozen(self, host_ip: str) -> bool:
        return self.frozen_hosts.get(host_ip, False)

    def freeze_host(self, host_ip: str) -> None:
        """
        Freezes baseline updates for host_ip to prevent learning attack behavior.
        """
        self.frozen_hosts[host_ip] = True

    def unfreeze_host(self, host_ip: str) -> None:
        """
        Resumes baseline updates for host_ip.
        """
        self.frozen_hosts[host_ip] = False

    def update_metric(self, host_ip: str, metric_name: str, value: float) -> None:
        """
        Updates running baseline for host_ip unless host is frozen.
        """
        if self.is_frozen(host_ip):
            return

        if host_ip not in self.metrics:
            self.metrics[host_ip] = {}

        if metric_name not in self.metrics[host_ip]:
            self.metrics[host_ip][metric_name] = WelfordAccumulator()

        self.metrics[host_ip][metric_name].update(value)

    def get_z_score(self, host_ip: str, metric_name: str, current_value: float) -> float:
        """
        Calculates how many standard deviations current_value is from host's normal baseline.
        Returns 0.0 if not enough samples or no baseline exists.
        """
        if host_ip not in self.metrics or metric_name not in self.metrics[host_ip]:
            return 0.0

        acc = self.metrics[host_ip][metric_name]
        if acc.count < self.warmup_samples:
            return 0.0

        return acc.z_score(current_value)

    def get_baseline_stats(self, host_ip: str) -> Dict[str, Dict[str, float]]:
        if host_ip not in self.metrics:
            return {}

        return {
            metric: {
                "mean": acc.mean,
                "stddev": acc.stddev,
                "count": float(acc.count),
            }
            for metric, acc in self.metrics[host_ip].items()
        }
