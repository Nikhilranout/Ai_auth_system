"""
API endpoints for behavior tracking.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from security.utils import parse_behavior_payload, safe_json_loads


@require_http_methods(["POST"])
@csrf_protect
def track_behavior(request):
    """Store sanitized behavior metrics in the session for the current login attempt."""
    try:
        hits = int(request.session.get('behavior_track_hits', 0))
        if hits >= 20:
            return JsonResponse({'success': False, 'error': 'Rate limit exceeded'}, status=429)

        request.session['behavior_track_hits'] = hits + 1
        payload = safe_json_loads(request.body.decode('utf-8'))
        metrics = parse_behavior_payload(payload)
        request.session['prefetched_behavior_data'] = metrics
        return JsonResponse({'success': True, 'stored': True})
    except Exception:
        return JsonResponse({'success': False, 'error': 'Invalid behavior payload'}, status=400)
