"""
Feature engineering module for ML.
"""

import numpy as np


class FeatureEngineer:
    """Feature engineering for behavioral biometrics."""
    
    @staticmethod
    def calculate_typing_pattern(behaviors):
        """Calculate typing pattern features."""
        if len(behaviors) < 2:
            return {
                'typing_consistency': 0.5,
                'typing_rhythm': 0.5,
                'mistake_ratio': 0.0
            }
        
        speeds = [b.typing_speed for b in behaviors if b.typing_speed > 0]
        intervals = [b.key_interval for b in behaviors if b.key_interval > 0]
        
        # Typing consistency (lower std = more consistent)
        if speeds:
            typing_consistency = 1 - min(np.std(speeds) / (np.mean(speeds) + 0.001), 1.0)
        else:
            typing_consistency = 0.5
        
        # Typing rhythm
        if intervals:
            typing_rhythm = 1 - min(np.std(intervals) / (np.mean(intervals) + 0.001), 1.0)
        else:
            typing_rhythm = 0.5
        
        # Mistake ratio
        total_keys = sum(b.click_count for b in behaviors)
        backspaces = sum(b.backspace_count for b in behaviors)
        mistake_ratio = (backspaces / (total_keys + 1)) if total_keys > 0 else 0
        
        return {
            'typing_consistency': max(0, min(typing_consistency, 1)),
            'typing_rhythm': max(0, min(typing_rhythm, 1)),
            'mistake_ratio': max(0, min(mistake_ratio, 1))
        }
    
    @staticmethod
    def calculate_mouse_pattern(behaviors):
        """Calculate mouse movement features."""
        if len(behaviors) < 1:
            return {
                'mouse_smoothness': 0.5,
                'click_pattern': 0.5,
                'movement_stability': 0.5
            }
        
        speeds = [b.mouse_speed for b in behaviors if b.mouse_speed > 0]
        click_intervals = [b.click_interval for b in behaviors if b.click_interval > 0]
        
        # Mouse smoothness
        if speeds:
            mouse_smoothness = 1 - min(np.std(speeds) / (np.mean(speeds) + 0.001), 1.0)
        else:
            mouse_smoothness = 0.5
        
        # Click pattern regularity
        if click_intervals:
            click_pattern = 1 - min(np.std(click_intervals) / (np.mean(click_intervals) + 0.001), 1.0)
        else:
            click_pattern = 0.5
        
        # Movement stability
        cursor_changes = sum(b.cursor_direction_changes for b in behaviors)
        avg_changes = cursor_changes / len(behaviors)
        movement_stability = 1 - min(avg_changes / 100, 1.0)
        
        return {
            'mouse_smoothness': max(0, min(mouse_smoothness, 1)),
            'click_pattern': max(0, min(click_pattern, 1)),
            'movement_stability': max(0, min(movement_stability, 1))
        }
    
    @staticmethod
    def calculate_device_consistency(user_behaviors):
        """Calculate device and location consistency."""
        if len(user_behaviors) < 2:
            return {
                'device_consistency': 0.5,
                'location_consistency': 0.5
            }
        
        devices = {}
        ips = {}
        
        for behavior in user_behaviors:
            devices[behavior.device_type] = devices.get(behavior.device_type, 0) + 1
            ips[behavior.ip_address] = ips.get(behavior.ip_address, 0) + 1
        
        # Device consistency (higher = more consistent)
        total = len(user_behaviors)
        device_consistency = max(devices.values()) / total if devices else 0.5
        
        # Location (IP) consistency
        location_consistency = max(ips.values()) / total if ips else 0.5
        
        return {
            'device_consistency': max(0, min(device_consistency, 1)),
            'location_consistency': max(0, min(location_consistency, 1))
        }
    
    @staticmethod
    def calculate_time_pattern(user_behaviors):
        """Calculate login time pattern."""
        if len(user_behaviors) < 2:
            return {
                'time_consistency': 0.5
            }
        
        hours = [b.login_time_hour for b in user_behaviors]
        
        # Check if login hours are consistent
        most_common_hour = max(set(hours), key=hours.count)
        hour_consistency = hours.count(most_common_hour) / len(hours)
        
        return {
            'time_consistency': max(0, min(hour_consistency, 1))
        }
