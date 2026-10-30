from datetime import datetime, timedelta
import pytest
from app.services.scoring import calculate_severity_score

def test_maximum_severity_score_cap():
    """Verify max inputs yield 100 and cannot exceed 100."""
    now = datetime.utcnow()
    score = calculate_severity_score(
        base_severity=100,
        source_confidence=100,
        last_seen=now,
        source_count=10
    )
    assert score == 100

def test_minimum_severity_score_zero():
    """Verify minimal inputs yield 0 points."""
    stale_date = datetime.utcnow() - timedelta(days=60)
    score = calculate_severity_score(
        base_severity=0,
        source_confidence=0,
        last_seen=stale_date,
        source_count=0
    )
    assert score == 0

def test_recency_decay_over_30_days():
    """Verify recency factor decays linearly from 20 points at day 0 to 0 points at day 30."""
    now = datetime.utcnow()
    day_0_score = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=now, source_count=1)
    
    day_15_date = now - timedelta(days=15)
    day_15_score = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=day_15_date, source_count=1)
    
    day_35_date = now - timedelta(days=35)
    day_35_score = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=day_35_date, source_count=1)

    # Day 0 recency adds 20 pts, Day 15 adds ~10 pts, Day 35 adds 0 pts
    assert day_0_score > day_15_score
    assert day_15_score > day_35_score
    assert day_0_score - day_35_score == 20

def test_multi_source_corroboration_factor():
    """Verify corroboration score scales up to 5 sources (max 10 points) and caps thereafter."""
    now = datetime.utcnow()
    single_source = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=now, source_count=1)
    three_sources = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=now, source_count=3)
    five_sources = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=now, source_count=5)
    ten_sources = calculate_severity_score(base_severity=50, source_confidence=50, last_seen=now, source_count=10)

    # 1 source adds 2 pts, 3 sources add 6 pts, 5 sources add 10 pts, 10 sources caps at 10 pts
    assert single_source < three_sources < five_sources
    assert five_sources == ten_sources

@pytest.mark.parametrize("base,conf,days,sources,expected_range", [
    (90, 95, 0, 4, (85, 100)),
    (50, 50, 10, 2, (45, 65)),
    (20, 30, 25, 1, (15, 30)),
    (95, 90, 45, 5, (70, 85)),
])
def test_table_driven_scoring_ranges(base, conf, days, sources, expected_range):
    """Table-driven verification of reproducible scoring behavior."""
    date = datetime.utcnow() - timedelta(days=days)
    score = calculate_severity_score(
        base_severity=base,
        source_confidence=conf,
        last_seen=date,
        source_count=sources
    )
    assert expected_range[0] <= score <= expected_range[1]

