"""
Model training module.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
from pathlib import Path
from django.conf import settings
from apps.accounts.models import BehaviorLog
from .preprocess import DataPreprocessor
import logging

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train ML models for behavioral authentication."""
    
    def __init__(self):
        self.preprocessor = DataPreprocessor()
        self.model = None
        self.model_type = 'random_forest'
        self.accuracy = 0
        self.model_version = 'v1.0'
    
    def prepare_training_data(self):
        """Prepare training data from behavior logs."""
        # Learn from actual historical outcomes instead of placeholder labels.
        behavior_logs = BehaviorLog.objects.select_related('user').exclude(
            authentication_outcome='pending'
        )

        if behavior_logs.count() < 2:
            logger.warning('Not enough data for training. Need at least 2 behavior logs.')
            return None, None
        
        # Create DataFrame
        df = self.preprocessor.create_dataframe(behavior_logs)
        
        # Create labels from verified outcomes.
        df['is_legitimate'] = 0
        for idx, log in enumerate(behavior_logs):
            legitimate = (
                log.authentication_outcome == 'success'
                and log.trust_score >= settings.TRUST_SCORE_SUSPICIOUS
            )
            df.at[idx, 'is_legitimate'] = int(legitimate)
        
        X = self.preprocessor.fit_transform(df)
        y = df['is_legitimate'].astype(int).values
        
        return X, y

    def _fit_and_evaluate(self, model, X, y):
        """Fit a model and evaluate it, even when data is very limited."""
        sample_count = len(X)
        class_count = len(np.unique(y))

        if sample_count < 5 or class_count < 2:
            logger.warning(
                'Training with a very small or single-class dataset (%s samples, %s classes). '
                'Using training data for evaluation only.',
                sample_count,
                class_count,
            )
            model.fit(X, y)
            y_pred = model.predict(X)
            accuracy = accuracy_score(y, y_pred)
            return model, accuracy, X, y, y_pred

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        return model, accuracy, X_test, y_test, y_pred
    
    def train_random_forest(self, X, y):
        """Train Random Forest model."""
        model = RandomForestClassifier(
            n_estimators=120,
            max_depth=8,
            min_samples_split=2,
            min_samples_leaf=2,
            class_weight='balanced_subsample',
            random_state=42,
            n_jobs=1
        )

        return self._fit_and_evaluate(model, X, y)
    
    def train_logistic_regression(self, X, y):
        """Train Logistic Regression model."""
        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            class_weight='balanced',
            n_jobs=1
        )

        return self._fit_and_evaluate(model, X, y)
    
    def train_decision_tree(self, X, y):
        """Train Decision Tree model."""
        model = DecisionTreeClassifier(
            max_depth=8,
            min_samples_split=2,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42
        )

        return self._fit_and_evaluate(model, X, y)
    
    def train(self, model_type='random_forest'):
        """Train the selected model."""
        logger.info(f'Starting model training with {model_type}...')
        
        # Prepare data
        X, y = self.prepare_training_data()
        if X is None:
            logger.error('Could not prepare training data.')
            return False
        
        # Train model
        if model_type == 'random_forest':
            self.model, self.accuracy, X_test, y_test, y_pred = self.train_random_forest(X, y)
        elif model_type == 'logistic_regression':
            self.model, self.accuracy, X_test, y_test, y_pred = self.train_logistic_regression(X, y)
        elif model_type == 'decision_tree':
            self.model, self.accuracy, X_test, y_test, y_pred = self.train_decision_tree(X, y)
        else:
            logger.error(f'Unknown model type: {model_type}')
            return False
        
        self.model_type = model_type
        
        # Log metrics
        logger.info(f'Model accuracy: {self.accuracy:.2%}')
        logger.info(f'Classification Report:\n{classification_report(y_test, y_pred, zero_division=0)}')
        logger.info(f'Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}')
        
        return True
    
    def save_model(self):
        """Save trained model and preprocessor."""
        if self.model is None:
            logger.error('No model to save.')
            return False
        
        models_dir = settings.ML_MODELS_DIR
        models_dir.mkdir(parents=True, exist_ok=True)
        
        model_path = models_dir / 'model.pkl'
        scaler_path = models_dir / 'scaler.pkl'
        
        try:
            joblib.dump(self.model, model_path)
            self.preprocessor.save_scaler(scaler_path)
            logger.info(f'Model saved to {model_path}')
            logger.info(f'Scaler saved to {scaler_path}')
            return True
        except Exception as e:
            logger.error(f'Error saving model: {e}')
            return False
    
    def get_model_info(self):
        """Get model information."""
        return {
            'model_type': self.model_type,
            'accuracy': self.accuracy,
            'model_version': self.model_version,
            'n_features': len(self.preprocessor.feature_names),
            'features': self.preprocessor.feature_names
        }
