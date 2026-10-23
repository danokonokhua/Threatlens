from datetime import datetime, timedelta

def calculate_severity_score(base_severity: int, source_confidence: int, last_seen: datetime, source_count: int) -> int:
    """
    Deterministic scoring model (0-100).
    Formula: (Base * 0.4) + (Confidence * 0.3) + (Recency * 0.2) + (Multi-Source * 0.1)
    """
    # 1. Base Severity (0-40 points)
    score = (base_severity / 100) * 40
    
    # 2. Source Confidence (0-30 points)
    score += (source_confidence / 100) * 30
    
    # 3. Recency Factor (0-20 points) - Decays over 30 days
    days_since_seen = (datetime.utcnow() - last_seen).days
    recency_factor = max(0, 1 - (days_since_seen / 30))
    score += recency_factor * 20
    
    # 4. Multi-Source Agreement (0-10 points) - Caps at 5 sources
    multi_source_factor = min(source_count, 5) / 5
    score += multi_source_factor * 10
    
    return min(100, int(score))