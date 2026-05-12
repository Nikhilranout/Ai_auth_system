"""
Model prediction module.
"""

from pathlib import Path
from django.conf import settings
from .preprocess import DataPreprocessor
from security.anomaly import calculate_anomaly_score
import logging

try:
    import joblib
except ImportError:
    joblib = None

logger = logging.getLogger(__name__)


class ModelPredictor:
    """Make predictions using trained models."""
    
    def __init__(self):
        self.model = None
        self.preprocessor = DataPreprocessor()
        self.load_model()
    
    def load_model(self):
        """Load trained model and preprocessor."""
        models_dir = settings.ML_MODELS_DIR
        model_path = models_dir / 'model.pkl'

        if joblib is None:
            logger.warning('joblib is not installed. Using heuristic fallback until ML dependencies are available.')
            return False
        
        if not model_path.exists():
            logger.info('Model file not found. Using heuristic fallback until a model is trained.')
            return False
        
        try:
            self.model = joblib.load(model_path)
            if not self.preprocessor.load_scaler():
                logger.info('Scaler file not found. Using heuristic fallback until training is completed.')
                self.model = None
                return False
            logger.info('Model loaded successfully.')
            return True
        except Exception as e:
            logger.error(f'Error loading model: {e}')
            return False

    def _confidence_to_weight(self, confidence):
        confidence = max(0.0, min(float(confidence or 0.0), 1.0))
        if confidence <= 0.2:
            return 0.2
        if confidence <= 0.4:
            return 0.35
        return min(0.75, 0.45 + (confidence * 0.3))

    def _build_context_score(self, behavior_log, anomaly):
        context_score = 85.0

        if anomaly['returning_device']:
            context_score += 6.0
        else:
            context_score -= 5.0

        if behavior_log.idle_ratio <= 0.35:
            context_score += 4.0
        elif behavior_log.idle_ratio >= 0.7:
            context_score -= 8.0

        if 6 <= behavior_log.typing_speed <= 14:
            context_score += 4.0
        elif behavior_log.typing_speed > 18 or (behavior_log.typing_speed > 0 and behavior_log.typing_speed < 1.0):
            context_score -= 10.0

        if behavior_log.correction_ratio <= 0.25:
            context_score += 3.0
        elif behavior_log.correction_ratio >= 0.55:
            context_score -= 8.0

        if behavior_log.paste_detected:
            context_score -= 4.0
        if behavior_log.autofill_detected:
            context_score -= 3.0
        if behavior_log.suspicious_input:
            context_score -= 15.0

        return max(0.0, min(context_score, 100.0))

    def _heuristic_predict(self, behavior_log):
        """Fallback trust scoring when the trained model is unavailable."""
        score = 62.0

        if 4.0 <= behavior_log.typing_speed <= 12.0:
            score += 10
        elif 2.0 <= behavior_log.typing_speed < 4.0:
            score += 4
        elif behavior_log.typing_speed > 18.0:
            score -= 10
        elif 0 < behavior_log.typing_speed < 1.0:
            score -= 12

        mouse_speed = behavior_log.mouse_avg_speed or behavior_log.mouse_speed
        if 80.0 <= mouse_speed <= 3200.0:
            score += 8
        elif 0 < mouse_speed < 20.0:
            score -= 6
        elif mouse_speed > 6000.0:
            score -= 12

        if behavior_log.backspace_count <= 6:
            score += 6
        elif behavior_log.backspace_count >= 18:
            score -= 8

        if behavior_log.correction_ratio <= 0.25:
            score += 6
        elif behavior_log.correction_ratio >= 0.6:
            score -= 10

        if behavior_log.idle_ratio <= 0.35:
            score += 5
        elif behavior_log.idle_ratio >= 0.65:
            score -= 8

        if 6 <= behavior_log.login_time_hour <= 23:
            score += 6
        else:
            score -= 5

        if behavior_log.cursor_direction_changes >= 3:
            score += 3

        if behavior_log.returning_device:
            score += 6

        if behavior_log.paste_detected or behavior_log.autofill_detected:
            score -= 3

        if behavior_log.suspicious_input:
            score -= 15

        trust_score = max(0.0, min(score, 100.0))
        return trust_score

    def _predict_ml_score(self, behavior_log):
        """Predict a score from the trained model when available."""
        heuristic_score = self._heuristic_predict(behavior_log)
        normalized_features = self.preprocessor.prepare_features(behavior_log)

        if self.model is None:
            return heuristic_score, 0.0, normalized_features

        # Prepare features
        features_dict = normalized_features

        # Create feature array in correct order
        features = [
            features_dict['typing_speed'],
            features_dict['key_interval'],
            features_dict['hold_time'],
            features_dict['backspace_count'],
            features_dict['mouse_speed'],
            features_dict['click_count'],
            features_dict['click_interval'],
            features_dict['hover_pause'],
            features_dict['login_time_hour'],
            features_dict['cursor_direction_changes'],
        ]

        # Scale features
        features_scaled = self.preprocessor.scaler.transform([features])

        # Get probability
        try:
            proba = self.model.predict_proba(features_scaled)[0]
            if len(proba) > 1:
                ml_score = max(0.0, min(proba[1] * 100.0, 100.0))
                confidence = abs(float(proba[1]) - 0.5) * 2.0
                return ml_score, confidence, features_dict
        except Exception:
            logger.info('Model does not expose predict_proba, falling back to class prediction.')

        prediction = self.model.predict(features_scaled)[0]
        if isinstance(prediction, (bool, int, float)):
            ml_score = max(0.0, min(float(prediction) * 100.0, 100.0))
            confidence = 0.6 if ml_score in (0.0, 100.0) else 0.3
            return ml_score, confidence, features_dict
        return heuristic_score, 0.0, features_dict

    def _score_to_label(self, trust_score):
        """Convert trust score into a label and risk level."""
        if trust_score >= settings.TRUST_SCORE_SAFE:
            return 'Genuine User', 'low'
        if trust_score >= settings.TRUST_SCORE_SUSPICIOUS:
            return 'OTP Verification Required', 'medium'
        return 'Suspicious User', 'high'
    
    def predict(self, behavior_log):
        """Predict login legitimacy for a behavior log."""
        try:
            heuristic_score = self._heuristic_predict(behavior_log)
            ml_score, ml_confidence, normalized_features = self._predict_ml_score(behavior_log)
            anomaly = calculate_anomaly_score(behavior_log)

            baseline = anomaly['baseline']
            baseline_sample = baseline.get('sample_size', 0)
            consistency_score = max(0.0, 100.0 - anomaly['score'])
            context_score = self._build_context_score(behavior_log, anomaly)
            ml_weight = self._confidence_to_weight(ml_confidence)
            blended_ml_score = (ml_score * ml_weight) + (heuristic_score * (1.0 - ml_weight))

            if baseline_sample < 3:
                trust_score = (blended_ml_score * 0.55) + (context_score * 0.30) + (consistency_score * 0.15)
            else:
                trust_score = (blended_ml_score * 0.45) + (consistency_score * 0.35) + (context_score * 0.20)

            trust_score = max(0.0, min(trust_score, 100.0))
            label, risk_level = self._score_to_label(trust_score)

            if behavior_log.suspicious_input and trust_score > settings.TRUST_SCORE_SUSPICIOUS:
                trust_score = max(float(settings.TRUST_SCORE_SUSPICIOUS) - 5.0, trust_score - 10.0)
                label, risk_level = self._score_to_label(trust_score)

            logger.info(
                'Behavior prediction: heuristic=%.2f ml=%.2f confidence=%.2f anomaly=%.2f context=%.2f trust=%.2f risk=%s label=%s normalized=%s',
                heuristic_score,
                ml_score,
                ml_confidence,
                anomaly['score'],
                context_score,
                trust_score,
                risk_level,
                label,
                normalized_features,
            )

            return {
                'trust_score': trust_score,
                'risk_level': risk_level,
                'prediction_label': label,
                'anomaly_score': anomaly['score'],
                'baseline_sample_size': baseline_sample,
                'anomaly_reasons': anomaly['reasons'],
                'ml_score': blended_ml_score,
            }
        except Exception as e:
            logger.error(f'Error making prediction: {e}')
            fallback = self._heuristic_predict(behavior_log)
            label, risk_level = self._score_to_label(fallback)
            return {
                'trust_score': fallback,
                'risk_level': risk_level,
                'prediction_label': label,
                'anomaly_score': 50.0 if behavior_log.suspicious_input else 25.0,
                'baseline_sample_size': 0,
                'anomaly_reasons': ['Predictor fallback'],
                'ml_score': fallback,
            }


def predict_trust_score(behavior_log):
    """Convenience function to predict trust score."""
    predictor = ModelPredictor()
    return predictor.predict(behavior_log)
