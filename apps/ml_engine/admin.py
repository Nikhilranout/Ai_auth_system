"""
Admin configuration for ML engine app.
"""

from django.contrib import admin
from .models import ModelMetrics


@admin.register(ModelMetrics)
class ModelMetricsAdmin(admin.ModelAdmin):
    """Model Metrics admin."""
    
    list_display = ('model_type', 'accuracy_display', 'is_active', 'trained_at')
    list_filter = ('model_type', 'is_active', 'trained_at')
    readonly_fields = ('created_at', 'trained_at')
    
    fieldsets = (
        ('Model Info', {'fields': ('model_type', 'is_active')}),
        ('Metrics', {'fields': ('accuracy', 'precision', 'recall', 'f1_score')}),
        ('Data', {'fields': ('total_samples', 'training_samples', 'test_samples')}),
        ('Timestamps', {'fields': ('created_at', 'trained_at')}),
    )
    
    def accuracy_display(self, obj):
        """Display accuracy as percentage."""
        return f"{obj.accuracy:.2%}"
    accuracy_display.short_description = 'Accuracy'
