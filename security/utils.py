"""Utility helpers for secure behavior tracking ingestion."""

from __future__ import annotations

import hashlib
import json
from typing import Any


MAX_BEHAVIOR_PAYLOAD_LENGTH = 15000


def safe_json_loads(raw_value: str | None, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse JSON into a dictionary with strict size and type checks."""
    if default is None:
        default = {}

    if not raw_value:
        return default

    raw_value = raw_value.strip()
    if not raw_value or len(raw_value) > MAX_BEHAVIOR_PAYLOAD_LENGTH:
        return default

    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default

    return parsed if isinstance(parsed, dict) else default


def clamp_float(value: Any, minimum: float = 0.0, maximum: float = 100000.0) -> float:
    """Convert a value to float and clamp it to a safe range."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = minimum
    return max(minimum, min(numeric, maximum))


def clamp_int(value: Any, minimum: int = 0, maximum: int = 100000) -> int:
    """Convert a value to int and clamp it to a safe range."""
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        numeric = minimum
    return max(minimum, min(numeric, maximum))


def clean_text(value: Any, maximum_length: int = 255) -> str:
    """Return a trimmed string value capped to a safe length."""
    if value is None:
        return ''
    text = str(value).strip()
    return text[:maximum_length]


def derive_device_fingerprint(*parts: Any) -> str:
    """Create a stable device fingerprint from non-secret client attributes."""
    normalized = '|'.join(clean_text(part, 255).lower() for part in parts if part is not None)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def parse_behavior_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize the behavior payload posted by the login tracker."""
    payload = payload or {}

    metrics = {
        'session_id': clean_text(payload.get('session_id'), 100),
        'device_fingerprint': clean_text(payload.get('device_fingerprint'), 255),
        'typing_speed': clamp_float(payload.get('typing_speed'), 0.0, 25.0),
        'avg_hold_time': clamp_float(payload.get('avg_hold_time'), 0.0, 5000.0),
        'avg_flight_time': clamp_float(payload.get('avg_flight_time'), 0.0, 5000.0),
        'total_typing_time': clamp_float(payload.get('total_typing_time'), 0.0, 120000.0),
        'pause_time': clamp_float(payload.get('pause_time'), 0.0, 120000.0),
        'hesitation_score': clamp_float(payload.get('hesitation_score'), 0.0, 100.0),
        'backspace_count': clamp_int(payload.get('backspace_count'), 0, 100),
        'delete_count': clamp_int(payload.get('delete_count'), 0, 100),
        'correction_ratio': clamp_float(payload.get('correction_ratio'), 0.0, 1.0),
        'retry_count': clamp_int(payload.get('retry_count'), 0, 100),
        'total_mouse_distance': clamp_float(payload.get('total_mouse_distance'), 0.0, 1000000.0),
        'mouse_avg_speed': clamp_float(payload.get('mouse_avg_speed'), 0.0, 8000.0),
        'click_count': clamp_int(payload.get('click_count'), 0, 100),
        'double_click_count': clamp_int(payload.get('double_click_count'), 0, 50),
        'click_rate': clamp_float(payload.get('click_rate'), 0.0, 10000.0),
        'idle_time': clamp_float(payload.get('idle_time'), 0.0, 120000.0),
        'idle_ratio': clamp_float(payload.get('idle_ratio'), 0.0, 1.0),
        'hover_pattern_score': clamp_float(payload.get('hover_pattern_score'), 0.0, 100.0),
        'hover_duration': clamp_float(payload.get('hover_duration'), 0.0, 120000.0),
        'direction_changes': clamp_int(payload.get('direction_changes'), 0, 100000),
        'field_transition_time': clamp_float(payload.get('field_transition_time'), 0.0, 120000.0),
        'submit_latency': clamp_float(payload.get('submit_latency'), 0.0, 120000.0),
        'screen_size': clean_text(payload.get('screen_size'), 50),
        'timezone': clean_text(payload.get('timezone'), 100),
        'language': clean_text(payload.get('language'), 20),
        'platform': clean_text(payload.get('platform'), 50),
        'browser': clean_text(payload.get('browser'), 50),
        'browser_version': clean_text(payload.get('browser_version'), 50),
        'device': clean_text(payload.get('device'), 50),
        'os': clean_text(payload.get('os'), 50),
        'returning_device': bool(payload.get('returning_device')),
        'paste_detected': bool(payload.get('paste_detected')),
        'autofill_detected': bool(payload.get('autofill_detected')),
        'tampered': bool(payload.get('tampered')),
        'login_started_at': clamp_float(payload.get('login_started_at'), 0.0, 9999999999999.0),
    }

    corrections = metrics['backspace_count'] + metrics['delete_count']
    metrics['correction_events'] = corrections

    if metrics['total_typing_time'] <= 0 or metrics['typing_speed'] <= 0:
        metrics['typing_speed'] = 0.0
        metrics['avg_hold_time'] = 0.0
        metrics['avg_flight_time'] = 0.0

    if metrics['click_count'] <= 1:
        metrics['click_rate'] = 0.0

    if metrics['mouse_avg_speed'] > 6000.0:
        metrics['mouse_avg_speed'] = 6000.0

    if corrections > 0 and corrections > max(5, metrics['typing_speed'] * 4):
        metrics['correction_ratio'] = min(metrics['correction_ratio'], 0.6)

    impossible_typing = (
        metrics['typing_speed'] > 18.0
        and metrics['avg_flight_time'] < 10.0
        and metrics['avg_hold_time'] < 10.0
        and metrics['total_typing_time'] > 0
    )
    impossible_mouse = (
        metrics['mouse_avg_speed'] > 6000.0
        and metrics['total_mouse_distance'] > 0
        and metrics['click_count'] == 0
    )
    impossible_click_pattern = (
        metrics['click_count'] > 20
        and metrics['click_rate'] > 0
        and metrics['click_rate'] < 20.0
    )

    metrics['suspicious_input'] = bool(
        metrics['tampered']
        or impossible_typing
        or impossible_mouse
        or impossible_click_pattern
    )

    return metrics
