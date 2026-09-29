from src.features.baseline import HostBaseline, WelfordAccumulator


def test_welford_accumulator():
    acc = WelfordAccumulator()
    values = [10.0, 20.0, 30.0]
    for v in values:
        acc.update(v)

    assert acc.count == 3
    assert acc.mean == 20.0
    assert round(acc.variance, 2) == 100.0


def test_baseline_freeze_contamination_prevention():
    hb = HostBaseline(warmup_samples=3)

    # Warmup with normal values around 100 pps
    for pps in [95.0, 100.0, 105.0]:
        hb.update_metric("10.0.0.1", "pps", pps)

    stats = hb.get_baseline_stats("10.0.0.1")
    assert stats["pps"]["mean"] == 100.0

    # High attack value Z-score
    z_score = hb.get_z_score("10.0.0.1", "pps", 2500.0)
    assert z_score > 10.0

    # Freeze baseline during alert
    hb.freeze_host("10.0.0.1")

    # Attempt to update with 2500 pps
    hb.update_metric("10.0.0.1", "pps", 2500.0)
    hb.update_metric("10.0.0.1", "pps", 2500.0)

    # Verify baseline mean remains 100.0 (uncontaminated!)
    stats_after = hb.get_baseline_stats("10.0.0.1")
    assert stats_after["pps"]["mean"] == 100.0
