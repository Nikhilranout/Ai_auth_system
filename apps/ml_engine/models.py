"""
Models for ML engine app.
"""

from django.db import models
import uuid


class ModelMetrics(models.Model):
    """Track ML model metrics and training history."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    model_type = models.CharField(max_length=50)
    accuracy = models.FloatField()
    precision = models.FloatField(default=0)
    recall = models.FloatField(default=0)
    f1_score = models.FloatField(default=0)
    
    total_samples = models.IntegerField(default=0)
    training_samples = models.IntegerField(default=0)
    test_samples = models.IntegerField(default=0)
    
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    trained_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.model_type} - Accuracy: {self.accuracy:.2%}"
    
    class Meta:
        verbose_name = "Model Metrics"
        verbose_name_plural = "Model Metrics"
        ordering = ['-trained_at']
