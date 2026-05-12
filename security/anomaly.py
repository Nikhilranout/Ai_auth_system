"""Baseline profiling and anomaly scoring for login behavior."""

from __future__ import annotations

from collections import Counter
from statistics import mean

from apps.accounts.models import BehaviorLog


def _average(values):
    usable = [float(value) for value in values if value is not None]
    return mean(usable) if usable else 0.0


def get_user_behavior_baseline(user, limit: int = 20) -> dict:
    """Build a lightweight baseline from prior successful behavior logs."""
    baseline_logs = list(
        BehaviorLog.objects.filter(
            user=user,
            authentication_outcome='success',
        ).order_by('-created_at')[:limit]
    )

    if not baseline_logs:
        return {
            'sample_size': 0,
            'avg_typing_speed': 0.0,
            'avg_hold_time': 0.0,
            'avg_flight_time': 0.0,
            'avg_mouse_speed': 0.0,
            'avg_idle_ratio': 0.0,
            'common_login_hour': None,
            'common_device': '',
            'common_browser': '',
            'common_timezone': '',
            'known_fingerprints': set(),
        }

    hours = [log.login_time_hour for log in baseline_logs]
    devices = [log.device or log.device_type for log in baseline_logs if (log.device or log.device_type)]
    browsers = [log.browser or log.browser_type for log in baseline_logs if (log.browser or log.browser_type)]
    timezones = [log.timezone for log in baseline_logs if log.timezone]
    fingerprints = {log.device_fingerprint for log in baseline_logs if log.device_fingerprint}

    return {
        'sample_size': len(baseline_logs),
        'avg_typing_speed': _average(log.typing_speed for log in baseline_logs),
        'avg_hold_time': _average(log.avg_hold_time or log.hold_time for log in baseline_logs),
        'avg_flight_time': _average(log.avg_flight_time or log.key_interval for log in baseline_logs),
        'avg_mouse_speed': _average(log.mouse_avg_speed or log.mouse_speed for log in baseline_logs),
        'avg_idle_ratio': _average(log.idle_ratio for log in baseline_logs),
        'common_login_hour': Counter(hours).most_common(1)[0][0] if hours else None,
        'common_device': Counter(devices).most_common(1)[0][0] if devices else '',
        'common_browser': Counter(browsers).most_common(1)[0][0] if browsers else '',
        'common_timezone': Counter(timezones).most_common(1)[0][0] if timezones else '',
        'known_fingerprints': fingerprints,
    }


def calculate_anomaly_score(behavior_log: BehaviorLog, baseline: dict | None = None) -> dict:
    """Compare a login attempt against the user's historical baseline."""
    baseline = baseline or get_user_behavior_baseline(behavior_log.user)
    sample_size = baseline.get('sample_size', 0)

    if sample_size == 0:
        return {
            'score': 15.0 if not behavior_log.suspicious_input else 45.0,
            'returning_device': behavior_log.returning_device,
            'baseline': baseline,
            'reasons': ['No baseline available'] if not behavior_log.suspicious_input else ['No baseline and suspicious input'],
        }

    def normalized_gap(current, expected, tolerance):
        if expected <= 0:
            return 0.0
        current = float(current or 0.0)
        expected = float(expected or 0.0)
        return min(abs(current - expected) / max(tolerance, expected * 0.6), 1.0)

    reasons = []
    anomaly = 0.0

    typing_gap = normalized_gap(behavior_log.typing_speed, baseline['avg_typing_speed'], 3.0)
    hold_gap = normalized_gap(behavior_log.avg_hold_time or behavior_log.hold_time, baseline['avg_hold_time'], 25.0)
    flight_gap = normalized_gap(behavior_log.avg_flight_time or behavior_log.key_interval, baseline['avg_flight_time'], 25.0)
    mouse_gap = normalized_gap(behavior_log.mouse_avg_speed or behavior_log.mouse_speed, baseline['avg_mouse_speed'], 40.0)
    idle_gap = normalized_gap(behavior_log.idle_ratio, baseline['avg_idle_ratio'], 0.1)

    anomaly += typing_gap * 16.0
    anomaly += hold_gap * 12.0
    anomaly += flight_gap * 12.0
    anomaly += mouse_gap * 10.0
    anomaly += idle_gap * 8.0

    if typing_gap >= 0.55:
        reasons.append('Typing rhythm differs from baseline')
    if hold_gap >= 0.6 or flight_gap >= 0.6:
        reasons.append('Keystroke timing differs from baseline')
    if mouse_gap >= 0.65:
        reasons.append('Mouse movement differs from baseline')

    common_hour = baseline.get('common_login_hour')
    if common_hour is not None and abs(behavior_log.login_time_hour - common_hour) >= 4:
        anomaly += 8.0
        reasons.append('Unusual login time')

    known_fingerprints = baseline.get('known_fingerprints', set())
    current_device = behavior_log.device or behavior_log.device_type
    current_browser = behavior_log.browser or behavior_log.browser_type
    behavior_log.returning_device = bool(
        behavior_log.device_fingerprint
        and behavior_log.device_fingerprint in known_fingerprints
    )

    if not behavior_log.returning_device:
        anomaly += 6.0
        reasons.append('New device fingerprint')

    if baseline.get('common_device') and current_device != baseline['common_device']:
        anomaly += 3.0
        reasons.append('Different device type')

    if baseline.get('common_browser') and current_browser != baseline['common_browser']:
        anomaly += 3.0
        reasons.append('Different browser')

    if baseline.get('common_timezone') and behavior_log.timezone and behavior_log.timezone != baseline['common_timezone']:
        anomaly += 3.0
        reasons.append('Different timezone')

    if behavior_log.suspicious_input:
        anomaly += 15.0
        reasons.append('Anti-tampering rule triggered')

    return {
        'score': max(0.0, min(anomaly, 100.0)),
        'returning_device': behavior_log.returning_device,
        'baseline': baseline,
        'reasons': reasons,
    }
