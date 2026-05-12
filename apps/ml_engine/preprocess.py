"""
Preprocessing module for ML.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from pathlib import Path
from django.conf import settings

try:
    import joblib
except ImportError:
    joblib = None


class DataPreprocessor:
    """Data preprocessing for behavioral biometrics."""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names = [
            'typing_speed', 'key_interval', 'hold_time', 'backspace_count',
            'mouse_speed', 'click_count', 'click_interval', 'hover_pause',
            'login_time_hour', 'cursor_direction_changes'
        ]

    def _safe_float(self, value, default=0.0, minimum=0.0, maximum=100000.0):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = default
        return max(minimum, min(numeric, maximum))

    def _safe_int(self, value, default=0, minimum=0, maximum=100000):
        try:
            numeric = int(value)
        except (TypeError, ValueError):
            numeric = default
        return max(minimum, min(numeric, maximum))
    
    def prepare_features(self, behavior_log):
        """Prepare features from a behavior log."""
        typing_speed = self._safe_float(getattr(behavior_log, 'typing_speed', 0.0), maximum=20.0)
        key_interval = self._safe_float(
            getattr(behavior_log, 'avg_flight_time', 0.0) or getattr(behavior_log, 'key_interval', 0.0),
            maximum=2000.0,
        )
        hold_time = self._safe_float(
            getattr(behavior_log, 'avg_hold_time', 0.0) or getattr(behavior_log, 'hold_time', 0.0),
            maximum=2000.0,
        )
        mouse_speed = self._safe_float(
            getattr(behavior_log, 'mouse_avg_speed', 0.0) or getattr(behavior_log, 'mouse_speed', 0.0),
            maximum=6000.0,
        )
        click_interval = self._safe_float(getattr(behavior_log, 'click_interval', 0.0), maximum=10000.0)
        hover_pause = self._safe_float(
            getattr(behavior_log, 'hover_pattern_score', 0.0) or getattr(behavior_log, 'hover_pause', 0.0),
            maximum=100.0,
        )

        features = {
            'typing_speed': typing_speed,
            'key_interval': key_interval,
            'hold_time': hold_time,
            'backspace_count': self._safe_int(getattr(behavior_log, 'backspace_count', 0), maximum=50),
            'mouse_speed': mouse_speed,
            'click_count': self._safe_int(getattr(behavior_log, 'click_count', 0), maximum=100),
            'click_interval': click_interval,
            'hover_pause': hover_pause,
            'login_time_hour': self._safe_int(getattr(behavior_log, 'login_time_hour', 0), maximum=23),
            'cursor_direction_changes': self._safe_int(getattr(behavior_log, 'cursor_direction_changes', 0), maximum=5000),
        }
        return features
    
    def create_dataframe(self, behavior_logs):
        """Create DataFrame from behavior logs."""
        data = []
        for log in behavior_logs:
            features = self.prepare_features(log)
            data.append(features)
        
        df = pd.DataFrame(data)
        return df
    
    def fit_scaler(self, df):
        """Fit scaler on data."""
        self.scaler.fit(df[self.feature_names])
    
    def transform(self, df):
        """Transform data using fitted scaler."""
        return self.scaler.transform(df[self.feature_names])
    
    def fit_transform(self, df):
        """Fit scaler and transform data."""
        self.fit_scaler(df)
        return self.transform(df)
    
    def save_scaler(self, path=None):
        """Save scaler to file."""
        if path is None:
            path = settings.ML_MODELS_DIR / 'scaler.pkl'
        if joblib is None:
            raise RuntimeError('joblib is required to save the scaler.')
        joblib.dump(self.scaler, path)
    
    def load_scaler(self, path=None):
        """Load scaler from file."""
        if joblib is None:
            return False
        if path is None:
            path = settings.ML_MODELS_DIR / 'scaler.pkl'
        if Path(path).exists():
            self.scaler = joblib.load(path)
            return True
        return False
