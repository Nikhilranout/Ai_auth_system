(function () {
    'use strict';

    function average(values) {
        var usable = values.filter(function (value) {
            return Number.isFinite(value) && value >= 0;
        });
        if (!usable.length) {
            return 0;
        }
        return usable.reduce(function (sum, value) {
            return sum + value;
        }, 0) / usable.length;
    }

    function clamp(value, minimum, maximum) {
        if (!Number.isFinite(value)) {
            return minimum;
        }
        return Math.min(Math.max(value, minimum), maximum);
    }

    function distance(a, b) {
        var dx = b.x - a.x;
        var dy = b.y - a.y;
        return Math.sqrt((dx * dx) + (dy * dy));
    }

    function detectBrowser() {
        var ua = navigator.userAgent || '';
        if (ua.indexOf('Edg/') >= 0) return 'Edge';
        if (ua.indexOf('Chrome/') >= 0) return 'Chrome';
        if (ua.indexOf('Firefox/') >= 0) return 'Firefox';
        if (ua.indexOf('Safari/') >= 0) return 'Safari';
        return 'Unknown';
    }

    function detectBrowserVersion() {
        var ua = navigator.userAgent || '';
        var match = ua.match(/(Edg|Chrome|Firefox|Version)\/([0-9.]+)/);
        return match ? match[2] : '';
    }

    function detectDevice() {
        if ((navigator.maxTouchPoints || 0) > 1 && window.innerWidth < 992) {
            return 'Mobile';
        }
        if ((navigator.maxTouchPoints || 0) > 1) {
            return 'Tablet';
        }
        return 'Desktop';
    }

    function detectOS() {
        var platform = navigator.platform || '';
        var ua = navigator.userAgent || '';
        if (/Win/i.test(platform)) return 'Windows';
        if (/Mac/i.test(platform)) return 'Mac';
        if (/Linux/i.test(platform)) return 'Linux';
        if (/Android/i.test(ua)) return 'Android';
        if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
        return 'Unknown';
    }

    function stableHash(input) {
        var hash = 0;
        var i;
        if (!input) return '0';
        for (i = 0; i < input.length; i += 1) {
            hash = ((hash << 5) - hash) + input.charCodeAt(i);
            hash |= 0;
        }
        return String(hash >>> 0);
    }

    function BehaviorTracker(form) {
        this.form = form;
        this.emailField = form.querySelector('#id_email');
        this.passwordField = form.querySelector('#id_password');
        this.hiddenField = form.querySelector('#behavior_data');
        this.submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
        this.startedAt = performance.now();
        this.lastActivityAt = this.startedAt;
        this.lastKeyUpAt = null;
        this.lastKeyDownAt = null;
        this.lastClickAt = null;
        this.lastDirection = null;
        this.lastMouseSample = null;
        this.currentHover = null;
        this.tampered = false;
        this.activeKeys = {};
        this.fieldState = {};
        this.metrics = {
            session_id: this.ensureSessionId(),
            device_fingerprint: '',
            typing_speed: 0,
            avg_hold_time: 0,
            avg_flight_time: 0,
            total_typing_time: 0,
            pause_time: 0,
            hesitation_score: 0,
            backspace_count: 0,
            delete_count: 0,
            correction_ratio: 0,
            retry_count: 0,
            total_mouse_distance: 0,
            mouse_avg_speed: 0,
            click_count: 0,
            double_click_count: 0,
            click_rate: 0,
            idle_time: 0,
            idle_ratio: 0,
            hover_pattern_score: 0,
            hover_duration: 0,
            direction_changes: 0,
            field_transition_time: 0,
            submit_latency: 0,
            screen_size: window.screen.width + 'x' + window.screen.height,
            timezone: this.getTimezone(),
            language: navigator.language || '',
            platform: navigator.platform || '',
            browser: detectBrowser(),
            browser_version: detectBrowserVersion(),
            device: detectDevice(),
            os: detectOS(),
            returning_device: false,
            paste_detected: false,
            autofill_detected: false,
            tampered: false,
            login_started_at: Date.now()
        };
        this.series = {
            holdTimes: [],
            flightTimes: [],
            pauses: [],
            mouseSpeeds: [],
            hoverDurations: [],
            clickIntervals: []
        };
        this.characterEvents = 0;
        this.init();
    }

    BehaviorTracker.prototype.ensureSessionId = function () {
        var key = 'ai_auth_behavior_session';
        var existing = window.sessionStorage.getItem(key);
        if (existing) {
            return existing;
        }
        existing = 'sess-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
        window.sessionStorage.setItem(key, existing);
        return existing;
    };

    BehaviorTracker.prototype.getTimezone = function () {
        try {
            return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        } catch (error) {
            return '';
        }
    };

    BehaviorTracker.prototype.buildFingerprint = function () {
        var seed = [
            navigator.userAgent || '',
            navigator.language || '',
            navigator.platform || '',
            this.metrics.screen_size,
            this.metrics.timezone,
            String(navigator.maxTouchPoints || 0)
        ].join('|');
        return stableHash(seed);
    };

    BehaviorTracker.prototype.loadKnownFingerprint = function () {
        var key = 'ai_auth_known_device';
        var known = window.localStorage.getItem(key);
        var current = this.buildFingerprint();
        this.metrics.device_fingerprint = current;
        this.metrics.returning_device = known === current;
    };

    BehaviorTracker.prototype.init = function () {
        if (!this.hiddenField || !this.emailField || !this.passwordField) {
            return;
        }

        this.loadKnownFingerprint();
        this.attachField(this.emailField);
        this.attachField(this.passwordField);

        document.addEventListener('mousemove', this.handleMouseMove.bind(this), { passive: true });
        document.addEventListener('mousedown', this.handleMouseDown.bind(this), { passive: true });
        document.addEventListener('click', this.handleClick.bind(this), { passive: true });
        document.addEventListener('visibilitychange', this.handleVisibilityChange.bind(this));
        this.form.addEventListener('submit', this.handleSubmit.bind(this));

        window.setTimeout(this.detectAutofill.bind(this), 350);
    };

    BehaviorTracker.prototype.attachField = function (field) {
        this.fieldState[field.id] = {
            focusAt: null,
            firstInputAt: null,
            lastBlurAt: null,
            visits: 0
        };

        field.addEventListener('focus', this.handleFocus.bind(this));
        field.addEventListener('blur', this.handleBlur.bind(this));
        field.addEventListener('keydown', this.handleKeyDown.bind(this));
        field.addEventListener('keyup', this.handleKeyUp.bind(this));
        field.addEventListener('input', this.handleInput.bind(this));
        field.addEventListener('paste', this.handlePaste.bind(this));
        field.addEventListener('mouseenter', this.handleHoverStart.bind(this));
        field.addEventListener('mouseleave', this.handleHoverEnd.bind(this));
    };

    BehaviorTracker.prototype.recordActivity = function () {
        var now = performance.now();
        var gap = now - this.lastActivityAt;
        if (gap > 1500) {
            this.metrics.idle_time += gap;
        }
        this.lastActivityAt = now;
    };

    BehaviorTracker.prototype.handleFocus = function (event) {
        var state = this.fieldState[event.target.id];
        var now = performance.now();
        this.recordActivity();

        if (state) {
            state.visits += 1;
            if (state.lastBlurAt) {
                this.metrics.retry_count += 1;
            }
            if (event.target.id === 'id_password' && this.fieldState.id_email && this.fieldState.id_email.lastBlurAt && !this.metrics.field_transition_time) {
                this.metrics.field_transition_time = now - this.fieldState.id_email.lastBlurAt;
            }
            state.focusAt = now;
        }
    };

    BehaviorTracker.prototype.handleBlur = function (event) {
        var state = this.fieldState[event.target.id];
        this.recordActivity();
        if (state) {
            state.lastBlurAt = performance.now();
        }
    };

    BehaviorTracker.prototype.handleInput = function (event) {
        var state = this.fieldState[event.target.id];
        this.recordActivity();
        if (state && state.firstInputAt === null) {
            state.firstInputAt = performance.now();
        }
    };

    BehaviorTracker.prototype.handlePaste = function () {
        this.metrics.paste_detected = true;
        this.recordActivity();
    };

    BehaviorTracker.prototype.handleKeyDown = function (event) {
        var now = performance.now();
        this.recordActivity();

        if (!this.activeKeys[event.code]) {
            this.activeKeys[event.code] = now;
        }

        if (this.lastKeyUpAt !== null) {
            var flightTime = now - this.lastKeyUpAt;
            if (flightTime >= 10 && flightTime <= 3000) {
                this.series.flightTimes.push(flightTime);
            }
            if (flightTime > 800 && flightTime <= 5000) {
                this.series.pauses.push(flightTime);
            }
        }

        this.lastKeyDownAt = now;

        if (event.key === 'Backspace') {
            this.metrics.backspace_count += 1;
        }
        if (event.key === 'Delete') {
            this.metrics.delete_count += 1;
        }
        if (event.key.length === 1) {
            this.characterEvents += 1;
        }
    };

    BehaviorTracker.prototype.handleKeyUp = function (event) {
        var now = performance.now();
        var keyDownAt = this.activeKeys[event.code];
        this.recordActivity();

        if (keyDownAt) {
            var holdTime = now - keyDownAt;
            if (holdTime >= 10 && holdTime <= 3000) {
                this.series.holdTimes.push(holdTime);
            }
            delete this.activeKeys[event.code];
        }

        this.lastKeyUpAt = now;
    };

    BehaviorTracker.prototype.handleMouseMove = function (event) {
        var now = performance.now();
        var sample = { x: event.clientX, y: event.clientY, t: now };
        this.recordActivity();

        if (this.lastMouseSample) {
            var elapsed = now - this.lastMouseSample.t;
            if (elapsed > 0) {
                var travelled = distance(this.lastMouseSample, sample);
                var speed = (travelled / elapsed) * 1000;
                if (elapsed >= 8 && travelled >= 0 && speed <= 8000) {
                    this.metrics.total_mouse_distance += travelled;
                    this.series.mouseSpeeds.push(speed);
                }

                if (travelled > 0) {
                    var direction = Math.atan2(sample.y - this.lastMouseSample.y, sample.x - this.lastMouseSample.x);
                    if (this.lastDirection !== null && Math.abs(direction - this.lastDirection) > (Math.PI / 3)) {
                        this.metrics.direction_changes += 1;
                    }
                    this.lastDirection = direction;
                }
            }
        }

        this.lastMouseSample = sample;
    };

    BehaviorTracker.prototype.handleMouseDown = function () {
        this.recordActivity();
    };

    BehaviorTracker.prototype.handleClick = function (event) {
        var now = performance.now();
        this.recordActivity();

        this.metrics.click_count += 1;

        if (event.detail >= 2) {
            this.metrics.double_click_count += 1;
        }

        if (this.lastClickAt !== null) {
            var clickInterval = now - this.lastClickAt;
            if (clickInterval >= 20 && clickInterval <= 10000) {
                this.series.clickIntervals.push(clickInterval);
            }
        }

        if (event.target === this.submitButton && !this.metrics.submit_latency) {
            this.metrics.submit_latency = now - this.startedAt;
        }

        this.lastClickAt = now;
    };

    BehaviorTracker.prototype.handleHoverStart = function (event) {
        this.currentHover = {
            target: event.target.id,
            startedAt: performance.now()
        };
        this.recordActivity();
    };

    BehaviorTracker.prototype.handleHoverEnd = function (event) {
        var now = performance.now();
        this.recordActivity();

        if (this.currentHover && this.currentHover.target === event.target.id) {
            var hoverTime = now - this.currentHover.startedAt;
            if (hoverTime >= 20 && hoverTime <= 10000) {
                this.series.hoverDurations.push(hoverTime);
                this.metrics.hover_duration += hoverTime;
            }
            this.currentHover = null;
        }
    };

    BehaviorTracker.prototype.handleVisibilityChange = function () {
        this.recordActivity();
        if (document.hidden) {
            this.metrics.idle_time += 500;
        }
    };

    BehaviorTracker.prototype.detectAutofill = function () {
        var fields = [this.emailField, this.passwordField];
        var hadKeyboardActivity = this.series.holdTimes.length > 0 || this.series.flightTimes.length > 0;
        if (!hadKeyboardActivity) {
            fields.forEach(function (field) {
                if (field && field.value) {
                    this.metrics.autofill_detected = true;
                }
            }, this);
        }
    };

    BehaviorTracker.prototype.finalize = function () {
        var now = performance.now();
        var totalElapsed = now - this.startedAt;
        var correctionCount = this.metrics.backspace_count + this.metrics.delete_count;
        var hoverAverage = average(this.series.hoverDurations);

        this.metrics.avg_hold_time = average(this.series.holdTimes);
        this.metrics.avg_flight_time = average(this.series.flightTimes);
        this.metrics.total_typing_time = 0;

        if (this.fieldState.id_email && this.fieldState.id_email.firstInputAt && this.fieldState.id_password && this.fieldState.id_password.lastBlurAt) {
            this.metrics.total_typing_time = this.fieldState.id_password.lastBlurAt - this.fieldState.id_email.firstInputAt;
        } else if (this.fieldState.id_password && this.fieldState.id_password.firstInputAt) {
            this.metrics.total_typing_time = now - this.fieldState.id_password.firstInputAt;
        }

        this.metrics.pause_time = this.series.pauses.reduce(function (sum, value) {
            return sum + value;
        }, 0);
        this.metrics.typing_speed = this.metrics.total_typing_time > 0
            ? (this.characterEvents / (this.metrics.total_typing_time / 1000))
            : 0;
        this.metrics.correction_ratio = this.characterEvents > 0
            ? Math.min(correctionCount / this.characterEvents, 1)
            : 0;
        this.metrics.mouse_avg_speed = average(this.series.mouseSpeeds);
        this.metrics.click_rate = average(this.series.clickIntervals);
        this.metrics.idle_ratio = totalElapsed > 0
            ? Math.min(this.metrics.idle_time / totalElapsed, 1)
            : 0;
        this.metrics.hover_pattern_score = hoverAverage > 0
            ? Math.min(100, (hoverAverage / Math.max(totalElapsed, 1)) * 1000)
            : 0;
        this.metrics.hesitation_score = Math.min(100, (
            (this.metrics.pause_time / Math.max(totalElapsed, 1)) * 100
        ) + (this.metrics.correction_ratio * 40));
        if (!this.metrics.submit_latency) {
            this.metrics.submit_latency = totalElapsed;
        }
        this.metrics.tampered = this.tampered;
        this.metrics.typing_speed = clamp(this.metrics.typing_speed, 0, 25);
        this.metrics.avg_hold_time = clamp(this.metrics.avg_hold_time, 0, 3000);
        this.metrics.avg_flight_time = clamp(this.metrics.avg_flight_time, 0, 3000);
        this.metrics.mouse_avg_speed = clamp(this.metrics.mouse_avg_speed, 0, 8000);
        this.metrics.click_rate = clamp(this.metrics.click_rate, 0, 10000);
        this.metrics.hover_pattern_score = clamp(this.metrics.hover_pattern_score, 0, 100);
        this.metrics.hesitation_score = clamp(this.metrics.hesitation_score, 0, 100);
    };

    BehaviorTracker.prototype.handleSubmit = function () {
        this.finalize();
        this.hiddenField.value = JSON.stringify(this.metrics);
    };

    document.addEventListener('DOMContentLoaded', function () {
        var form = document.getElementById('loginForm');
        if (!form) {
            return;
        }
        window.behaviorTracker = new BehaviorTracker(form);
    });
}());
