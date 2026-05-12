/**
 * Behavioral Biometrics Tracking Module
 * Tracks user behavior during login (typing patterns, mouse movements, etc.)
 */

class BehavioralBiometrics {
    constructor() {
        this.typing_speeds = [];
        this.key_intervals = [];
        this.key_hold_times = [];
        this.backspace_count = 0;
        this.mistake_corrections = 0;
        
        this.mouse_positions = [];
        this.mouse_speeds = [];
        this.click_intervals = [];
        this.click_count = 0;
        this.hover_times = [];
        this.cursor_direction_changes = 0;
        
        this.form = null;
        this.passwordField = null;
        this.emailField = null;
        
        this.lastKeyTime = 0;
        this.lastMousePos = { x: 0, y: 0 };
        this.lastClickTime = 0;
        this.lastMouseMove = 0;
        
        this.init();
    }
    
    init() {
        // Find form and fields
        this.form = document.getElementById('loginForm');
        this.passwordField = document.getElementById('id_password');
        this.emailField = document.getElementById('id_email');
        
        if (!this.form) return;
        
        // Attach event listeners
        if (this.passwordField) {
            this.passwordField.addEventListener('keydown', this.handleKeyDown.bind(this));
            this.passwordField.addEventListener('keyup', this.handleKeyUp.bind(this));
            this.passwordField.addEventListener('mousemove', this.handleMouseMove.bind(this));
            this.passwordField.addEventListener('click', this.handleClick.bind(this));
            this.passwordField.addEventListener('focus', this.handleFocus.bind(this));
        }
        
        if (this.emailField) {
            this.emailField.addEventListener('keydown', this.handleKeyDown.bind(this));
            this.emailField.addEventListener('keyup', this.handleKeyUp.bind(this));
        }
        
        document.addEventListener('mousemove', this.handleDocumentMouseMove.bind(this));
        this.form.addEventListener('submit', this.handleFormSubmit.bind(this));
    }
    
    handleKeyDown(event) {
        const currentTime = Date.now();
        
        // Track key intervals
        if (this.lastKeyTime > 0) {
            const interval = currentTime - this.lastKeyTime;
            this.key_intervals.push(interval);
        }
        
        this.lastKeyTime = currentTime;
        
        // Track backspace and corrections
        if (event.key === 'Backspace') {
            this.backspace_count++;
            this.mistake_corrections++;
        }
    }
    
    handleKeyUp(event) {
        const currentTime = Date.now();
        
        if (this.lastKeyTime > 0) {
            const holdTime = currentTime - this.lastKeyTime;
            this.key_hold_times.push(holdTime);
        }
        
        // Calculate typing speed (characters per second)
        const targetLength = this.passwordField.value.length;
        const elapsed = (currentTime - this.form.dataset.startTime || 0) / 1000;
        if (elapsed > 0) {
            const typingSpeed = targetLength / elapsed;
            this.typing_speeds.push(typingSpeed);
        }
    }
    
    handleMouseMove(event) {
        const currentTime = Date.now();
        const currentPos = { x: event.clientX, y: event.clientY };
        
        // Calculate mouse speed
        if (this.lastMouseMove > 0) {
            const timeDiff = (currentTime - this.lastMouseMove) / 1000; // Convert to seconds
            if (timeDiff > 0) {
                const distance = Math.sqrt(
                    Math.pow(currentPos.x - this.lastMousePos.x, 2) +
                    Math.pow(currentPos.y - this.lastMousePos.y, 2)
                );
                const speed = distance / timeDiff;
                this.mouse_speeds.push(speed);
            }
        }
        
        this.lastMousePos = currentPos;
        this.lastMouseMove = currentTime;
        this.mouse_positions.push(currentPos);
        
        // Detect cursor direction changes
        if (this.mouse_positions.length >= 3) {
            const prev = this.mouse_positions[this.mouse_positions.length - 2];
            const curr = this.mouse_positions[this.mouse_positions.length - 1];
            const next = this.mouse_positions[this.mouse_positions.length - 3];
            
            const angle1 = Math.atan2(curr.y - prev.y, curr.x - prev.x);
            const angle2 = Math.atan2(next.y - curr.y, next.x - curr.x);
            const angleDiff = Math.abs(angle1 - angle2);
            
            if (angleDiff > Math.PI / 4) { // More than 45 degrees
                this.cursor_direction_changes++;
            }
        }
    }
    
    handleDocumentMouseMove(event) {
        if (!this.form.contains(event.target)) return;
        this.handleMouseMove(event);
    }
    
    handleClick(event) {
        this.click_count++;
        const currentTime = Date.now();
        
        if (this.lastClickTime > 0) {
            const interval = (currentTime - this.lastClickTime) / 1000; // Convert to seconds
            this.click_intervals.push(interval);
        }
        
        this.lastClickTime = currentTime;
    }
    
    handleFocus(event) {
        // Mark start time for typing speed calculation
        this.form.dataset.startTime = Date.now();
    }
    
    handleFormSubmit(event) {
        // Calculate averages
        const avgTypingSpeed = this.calculateAverage(this.typing_speeds);
        const avgKeyInterval = this.calculateAverage(this.key_intervals);
        const avgHoldTime = this.calculateAverage(this.key_hold_times);
        const avgMouseSpeed = this.calculateAverage(this.mouse_speeds);
        const avgClickInterval = this.calculateAverage(this.click_intervals);
        
        // Prepare behavior data
        const behaviorData = {
            typing_speed: avgTypingSpeed,
            key_interval: avgKeyInterval,
            hold_time: avgHoldTime,
            backspace_count: this.backspace_count,
            mouse_speed: avgMouseSpeed,
            click_count: this.click_count,
            click_interval: avgClickInterval,
            cursor_direction_changes: this.cursor_direction_changes,
            login_timestamp: Date.now()
        };
        
        // Store in hidden field
        const behaviorInput = document.getElementById('behavior_data');
        if (behaviorInput) {
            behaviorInput.value = JSON.stringify(behaviorData);
        }
    }
    
    calculateAverage(array) {
        if (array.length === 0) return 0;
        const sum = array.reduce((a, b) => a + b, 0);
        return sum / array.length;
    }
    
    // Get all collected data
    getData() {
        return {
            typing_speed: this.calculateAverage(this.typing_speeds),
            key_interval: this.calculateAverage(this.key_intervals),
            hold_time: this.calculateAverage(this.key_hold_times),
            backspace_count: this.backspace_count,
            mistake_corrections: this.mistake_corrections,
            mouse_speed: this.calculateAverage(this.mouse_speeds),
            click_count: this.click_count,
            click_interval: this.calculateAverage(this.click_intervals),
            hover_times: this.hover_times,
            cursor_direction_changes: this.cursor_direction_changes,
            total_mouse_movements: this.mouse_positions.length,
            total_key_presses: this.typing_speeds.length
        };
    }
}

// Initialize biometrics tracking when page loads
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('loginForm')) {
        window.biometrics = new BehavioralBiometrics();
    }
});
