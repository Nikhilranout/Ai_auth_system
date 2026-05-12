"""
Views for ML engine app.
"""

from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db import models
from apps.accounts.models import BehaviorLog, LoginLog
from apps.accounts.models import User
from .models import ModelMetrics
import logging

logger = logging.getLogger(__name__)


@staff_member_required
def model_dashboard(request):
    """ML Model Dashboard for admin."""
    
    # Get latest model metrics
    latest_metrics = ModelMetrics.objects.filter(is_active=True).first()
    
    # Get behavior statistics
    total_behaviors = BehaviorLog.objects.count()
    users_with_data = User.objects.filter(behavior_logs__isnull=False).distinct().count()
    
    # Risk level distribution
    risk_distribution = BehaviorLog.objects.values('risk_level').annotate(
        count=models.Count('id')
    )
    
    # Login success rate
    total_logins = LoginLog.objects.count()
    successful_logins = LoginLog.objects.filter(status='success').count()
    success_rate = (successful_logins / total_logins * 100) if total_logins > 0 else 0
    
    context = {
        'latest_metrics': latest_metrics,
        'total_behaviors': total_behaviors,
        'users_with_data': users_with_data,
        'risk_distribution': risk_distribution,
        'total_logins': total_logins,
        'successful_logins': successful_logins,
        'success_rate': success_rate,
    }
    
    return render(request, 'ml_engine/dashboard.html', context)


@staff_member_required
def train_model_view(request):
    """Train ML model."""
    
    if request.method == 'POST':
        model_type = request.POST.get('model_type', 'random_forest')
        
        try:
            from .train_model import ModelTrainer

            trainer = ModelTrainer()
            success = trainer.train(model_type=model_type)
            
            if success:
                trainer.save_model()
                
                # Save metrics
                ModelMetrics.objects.filter(is_active=True).update(is_active=False)
                ModelMetrics.objects.create(
                    model_type=model_type,
                    accuracy=trainer.accuracy,
                    is_active=True,
                )
                
                message = f'Model trained successfully. Accuracy: {trainer.accuracy:.2%}'
                return JsonResponse({'success': True, 'message': message})
            else:
                return JsonResponse({'success': False, 'message': 'Training failed.'})
        
        except Exception as e:
            logger.error(f'Model training error: {e}')
            return JsonResponse({'success': False, 'message': str(e)})
    
    context = {}
    return render(request, 'ml_engine/train.html', context)


@login_required
def model_info_view(request):
    """Get model information."""
    
    try:
        from .predict import ModelPredictor

        predictor = ModelPredictor()
        latest_metrics = ModelMetrics.objects.filter(is_active=True).first()
        
        info = {
            'model_loaded': predictor.model is not None,
            'model_type': latest_metrics.model_type if latest_metrics else 'Unknown',
            'accuracy': latest_metrics.accuracy if latest_metrics else 0,
        }
        
        return JsonResponse(info)
    except Exception as e:
        logger.error(f'Error getting model info: {e}')
        return JsonResponse({'error': str(e)}, status=500)
