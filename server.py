#session hijacking and bots attack


from flask import Flask, request, make_response, redirect, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_socketio import SocketIO
import uuid
import time
from datetime import datetime
import random
import json
from collections import defaultdict
import threading
import socket

app = Flask(__name__)
app.secret_key = 'super-secret-key'
socketio = SocketIO(app)

# Data storage
sessions = {}
attack_logs = []
ip_reputation = defaultdict(dict)
monitoring_clients = set()
recent_attacks = []  # New global variable to store recent attacks

# Configuration
HONEYPOT_FIELD_NAME = "super_secret_field"
HONEYPOT_FIELD_NAME_2 = "website_url"  # Second honeypot field
HONEYPOT_FIELD_NAME_3 = "email_confirm"  # Third honeypot field
HONEYPOT_LINK_PREFIX = "hidden-admin-"
BLACKLIST_THRESHOLD = 3
REQUEST_RATE_LIMIT = 10  # requests per minute
SLOW_DOWN_DURATION = 60  # seconds
MIN_PAGE_LOAD_TIME = 0.5  # minimum time in seconds for a page load
MAX_CLICK_SPEED = 0.1  # maximum time between clicks in seconds
MIN_SCROLL_DEPTH = 0.2  # minimum scroll depth as percentage
MIN_MOUSE_MOVEMENTS = 5  # minimum number of mouse movements
MIN_TIME_ON_PAGE = 2  # minimum time in seconds on a page
MAX_REQUESTS_PER_SESSION = 50  # maximum requests per session

# Attack simulation flags
SIMULATE_SCRAPING = True
SIMULATE_BOT_ATTACK = True
SIMULATE_SESSION_HIJACKING = True

class AttackDetector:
    @staticmethod
    def detect_session_hijacking(session_id, current_request):
        if session_id not in sessions:
            return False
        
        session = sessions[session_id]
        mismatches = []
        
        # Check IP change
        if session['ip'] != current_request.remote_addr:
            mismatches.append(f"IP changed from {session['ip']} to {current_request.remote_addr}")
        
        # Check User-Agent change
        if session['user_agent'] != current_request.headers.get('User-Agent'):
            mismatches.append("User-Agent changed")
        
        # Check device fingerprint if available
        if 'fingerprint' in session and 'fingerprint' in current_request.args:
            if session['fingerprint'] != current_request.args.get('fingerprint'):
                mismatches.append("Device fingerprint changed")
        
        if mismatches:
            log_attack(
                attack_type="Session Hijacking Attempt",
                ip=current_request.remote_addr,
                session_id=session_id,
                details=" | ".join(mismatches),
                page=current_request.path
            )
            return True
        return False
    
    @staticmethod
    def detect_scraping(session_id, current_request):
        # Check for honeypot field submissions
        honeypot_fields = [HONEYPOT_FIELD_NAME, HONEYPOT_FIELD_NAME_2, HONEYPOT_FIELD_NAME_3]
        for field in honeypot_fields:
            if field in current_request.form and current_request.form[field]:
                log_attack(
                    attack_type="Scraping Bot Detected",
                    ip=current_request.remote_addr,
                    session_id=session_id,
                    details=f"Honeypot field '{field}' filled",
                    page=current_request.path
                )
                return True
        
        # Check for honeypot link clicks
        if any(HONEYPOT_LINK_PREFIX in key for key in current_request.args):
            log_attack(
                attack_type="Scraping Bot Detected",
                ip=current_request.remote_addr,
                session_id=session_id,
                details="Honeypot link clicked",
                page=current_request.path
            )
            return True
        
        # Check for missing mouse movement data
        if 'has_mouse_movement' not in current_request.args:
            log_attack(
                attack_type="Possible Scraping Detected",
                ip=current_request.remote_addr,
                session_id=session_id,
                details="No mouse movement detected",
                page=current_request.path
            )
            return True
        
        # Check for missing scroll data
        if 'scroll_depth' not in current_request.args:
            log_attack(
                attack_type="Possible Scraping Detected",
                ip=current_request.remote_addr,
                session_id=session_id,
                details="No scroll activity detected",
                page=current_request.path
            )
            return True
        
        # Check for suspiciously fast page interactions
        if 'page_load_time' in current_request.args:
            load_time = float(current_request.args.get('page_load_time', 0))
            if load_time < MIN_PAGE_LOAD_TIME:
                log_attack(
                    attack_type="Bot-like Behavior",
                    ip=current_request.remote_addr,
                    session_id=session_id,
                    details=f"Suspiciously fast page load: {load_time:.2f}s",
                    page=current_request.path
                )
                return True
        
        # Check for insufficient mouse movements
        if 'mouse_movement_count' in current_request.args:
            movement_count = int(current_request.args.get('mouse_movement_count', 0))
            if movement_count < MIN_MOUSE_MOVEMENTS:
                log_attack(
                    attack_type="Bot-like Behavior",
                    ip=current_request.remote_addr,
                    session_id=session_id,
                    details=f"Insufficient mouse movements: {movement_count}",
                    page=current_request.path
                )
                return True
        
        # Check for insufficient time on page
        if 'time_on_page' in current_request.args:
            time_on_page = float(current_request.args.get('time_on_page', 0))
            if time_on_page < MIN_TIME_ON_PAGE:
                log_attack(
                    attack_type="Bot-like Behavior",
                    ip=current_request.remote_addr,
                    session_id=session_id,
                    details=f"Too little time on page: {time_on_page:.2f}s",
                    page=current_request.path
                )
                return True
        
        return False
    
    @staticmethod
    def detect_bot_behavior(session_id, current_request):
        # Check request rate
        ip = current_request.remote_addr
        if ip in ip_reputation and 'request_times' in ip_reputation[ip]:
            request_times = ip_reputation[ip]['request_times']
            now = time.time()
            recent_requests = [t for t in request_times if now - t < 60]
            
            if len(recent_requests) > REQUEST_RATE_LIMIT:
                log_attack(
                    attack_type="Bot-like Behavior",
                    ip=ip,
                    session_id=session_id,
                    details=f"High request rate: {len(recent_requests)} requests/minute",
                    page=current_request.path
                )
                return True
            
            # Check for request patterns
            if len(recent_requests) > 3:
                intervals = [recent_requests[i] - recent_requests[i-1] for i in range(1, len(recent_requests))]
                if all(abs(i - intervals[0]) < 0.1 for i in intervals):  # Too regular intervals
                    log_attack(
                        attack_type="Bot-like Behavior",
                        ip=ip,
                        session_id=session_id,
                        details="Suspiciously regular request pattern",
                        page=current_request.path
                    )
                    return True
        
        # Check session request count
        if session_id in sessions:
            if 'request_count' not in sessions[session_id]:
                sessions[session_id]['request_count'] = 0
            sessions[session_id]['request_count'] += 1
            
            if sessions[session_id]['request_count'] > MAX_REQUESTS_PER_SESSION:
                log_attack(
                    attack_type="Bot-like Behavior",
                    ip=ip,
                    session_id=session_id,
                    details=f"Too many requests in session: {sessions[session_id]['request_count']}",
                    page=current_request.path
                )
                return True
        
        return False

class PreventionSystem:
    @staticmethod
    def block_ip(ip):
        print(f"[DEBUG] Blocking IP: {ip}")
        if ip not in ip_reputation:
            ip_reputation[ip] = {'attack_count': 0, 'request_times': []}
        ip_reputation[ip]['blocked'] = True
        ip_reputation[ip]['blocked_until'] = time.time() + 3600  # 1 hour block
        log_action(f"Blocked IP {ip}", "Prevention System")
        # Emit update to dashboard
        attack_types = defaultdict(int)
        for attack in attack_logs:
            if 'type' in attack:
                attack_types[attack['type']] += 1
        socketio.emit('update_stats', {
            'attack_types': attack_types,
            'blocked_ips': len([ip for ip, rep in ip_reputation.items() if rep.get('blocked', False)])
        }, namespace='/monitoring')
        # Also emit session update in case session status changed
        socketio.emit('update_sessions', sessions, namespace='/monitoring')
    
    @staticmethod
    def slow_down_ip(ip):
        ip_reputation[ip]['slowed'] = True
        ip_reputation[ip]['slowed_until'] = time.time() + SLOW_DOWN_DURATION
        log_action(f"Slowed down IP {ip}", "Prevention System")
    
    @staticmethod
    def check_ip_reputation(ip):
        if ip in ip_reputation:
            rep = ip_reputation[ip]
            if rep.get('blocked', False) and rep['blocked_until'] > time.time():
                return "blocked"
            if rep.get('slowed', False) and rep['slowed_until'] > time.time():
                return "slowed"
            if rep.get('attack_count', 0) >= BLACKLIST_THRESHOLD:
                PreventionSystem.block_ip(ip)
                return "blocked"
        return "clean"

def log_attack(attack_type, ip, session_id=None, details="", page=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'type': attack_type,
        'ip': ip,
        'session_id': session_id,
        'details': details,
        'page': page or 'Unknown'
    }
    attack_logs.append(log_entry)
    recent_attacks.append(log_entry)
    
    # Keep only last 100 recent attacks
    if len(recent_attacks) > 100:
        recent_attacks.pop(0)
    
    # Update IP reputation
    if ip not in ip_reputation:
        ip_reputation[ip] = {'attack_count': 0, 'request_times': []}
    ip_reputation[ip]['attack_count'] += 1
    ip_reputation[ip]['last_attack'] = timestamp
    
    # Notify monitoring clients
    socketio.emit('new_attack', log_entry, namespace='/monitoring')
    
    # Update attack types distribution
    attack_types = defaultdict(int)
    for attack in attack_logs:
        attack_types[attack['type']] += 1
    socketio.emit('update_stats', {
        'attack_types': attack_types,
        'blocked_ips': len([ip for ip, rep in ip_reputation.items() if rep.get('blocked', False)])
    }, namespace='/monitoring')
    
    print(f"[ATTACK DETECTED] {timestamp} - {attack_type} from {ip} on {page} - {details}")

def log_action(action, source):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'action': action,
        'source': source
    }
    attack_logs.append(log_entry)
    socketio.emit('new_action', log_entry, namespace='/monitoring')
    print(f"[ACTION TAKEN] {timestamp} - {source}: {action}")

# Main application routes
@app.route('/')
def home():
    # Check if IP is blocked
    ip_status = PreventionSystem.check_ip_reputation(request.remote_addr)
    if ip_status == "blocked":
        return render_template_string('''
            <h1 style="color: red;">Access Denied</h1>
            <p>Your IP address has been blocked due to suspicious activity.</p>
        '''),403
    elif ip_status == "slowed":
        time.sleep(3)  # Simulate slow down
    
    # Track request
    if request.remote_addr in ip_reputation:
        ip_reputation[request.remote_addr]['request_times'].append(time.time())
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Application Portal</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f5f5f5; }
                .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }
                .menu { margin-top: 20px; }
                .menu a { display: inline-block; margin-right: 15px; padding: 10px 15px; background: #3498db; color: white; text-decoration: none; border-radius: 4px; }
                .menu a:hover { background: #2980b9; }
                .hidden-field { display: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to Secure Application</h1>
                <p>Please select an option:</p>
                
                <div class="menu">
                    <a href="/login">Login</a>
                    <a href="/register">Register</a>
                    <a href="/products">View Products</a>
                </div>
                
                <!-- Hidden honeypot link for bots -->
                <div style="display: none;">
                    <a href="/secret-admin-page">Admin Panel</a>
                </div>
            </div>
            
            <script>
                // Track mouse movement for scraping detection
                document.addEventListener('mousemove', function() {
                    // In a real system, we'd send this to the server periodically
                    sessionStorage.setItem('has_mouse_movement', 'true');
                });
            </script>
        </body>
        </html>
    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    ip_status = PreventionSystem.check_ip_reputation(request.remote_addr)
    if ip_status == "blocked":
        return render_template_string('<h1 style="color: red;">Access Denied</h1>', 403)
    elif ip_status == "slowed":
        time.sleep(3)
    
    if request.method == 'POST':
        # Check honeypot field
        if HONEYPOT_FIELD_NAME in request.form and request.form[HONEYPOT_FIELD_NAME]:
            AttackDetector.detect_scraping(None, request)
            return "Invalid request", 400
        
        # Create session
        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            'username': request.form.get('username'),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'created': time.time(),
            'status': 'Normal',
            'fingerprint': request.form.get('fingerprint', ''),
            'last_activity': time.time()
        }
        
        # Notify monitoring clients about new session
        socketio.emit('update_sessions', sessions, namespace='/monitoring')
        
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('session_id', session_id, httponly=True)
        return resp
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px; }
                .login-form { background: #f9f9f9; padding: 20px; border-radius: 5px; }
                .form-group { margin-bottom: 15px; }
                label { display: block; margin-bottom: 5px; }
                input { width: 100%; padding: 8px; box-sizing: border-box; }
                button { background: #4CAF50; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
                .hidden-field { display: none; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Login</h2>
                <form method="post" id="loginForm">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <!-- Honeypot fields -->
                    <div class="hidden-field">
                        <label for="{{ HONEYPOT_FIELD_NAME }}">Leave this blank:</label>
                        <input type="text" id="{{ HONEYPOT_FIELD_NAME }}" name="{{ HONEYPOT_FIELD_NAME }}">
                    </div>
                    <div class="hidden-field">
                        <label for="{{ HONEYPOT_FIELD_NAME_2 }}">Website URL (leave blank):</label>
                        <input type="url" id="{{ HONEYPOT_FIELD_NAME_2 }}" name="{{ HONEYPOT_FIELD_NAME_2 }}">
                    </div>
                    <div class="hidden-field">
                        <label for="{{ HONEYPOT_FIELD_NAME_3 }}">Email confirmation (leave blank):</label>
                        <input type="email" id="{{ HONEYPOT_FIELD_NAME_3 }}" name="{{ HONEYPOT_FIELD_NAME_3 }}">
                    </div>
                    <div class="form-group">
                        <label for="fingerprint">Device ID (auto-filled):</label>
                        <input type="text" id="fingerprint" name="fingerprint" value="{{ fingerprint }}">
                    </div>
                    <button type="submit">Login</button>
                </form>
            </div>
            <script>
                // Generate simple fingerprint
                document.getElementById('fingerprint').value = 
                    navigator.userAgent + '|' + screen.width + 'x' + screen.height + '|' + 
                    navigator.hardwareConcurrency + '|' + navigator.language;
                
                // Track user behavior
                let mouseMoved = false;
                let lastClickTime = 0;
                let maxScrollDepth = 0;
                let pageLoadTime = performance.now();
                
                // Track mouse movement
                document.addEventListener('mousemove', function() {
                    mouseMoved = true;
                    sessionStorage.setItem('has_mouse_movement', 'true');
                });
                
                // Track clicks
                document.addEventListener('click', function() {
                    const now = performance.now();
                    const timeSinceLastClick = now - lastClickTime;
                    lastClickTime = now;
                    
                    if (timeSinceLastClick > 0 && timeSinceLastClick < 100) {
                        sessionStorage.setItem('last_click_time', timeSinceLastClick.toString());
                    }
                });
                
                // Track scrolling
                document.addEventListener('scroll', function() {
                    const scrollDepth = (window.scrollY + window.innerHeight) / document.documentElement.scrollHeight;
                    maxScrollDepth = Math.max(maxScrollDepth, scrollDepth);
                    sessionStorage.setItem('scroll_depth', maxScrollDepth.toString());
                });
                
                // Add behavior data to form submission
                document.getElementById('loginForm').addEventListener('submit', function(e) {
                    const hasMouseMove = sessionStorage.getItem('has_mouse_movement') || 'false';
                    const scrollDepth = sessionStorage.getItem('scroll_depth') || '0';
                    const lastClickTime = sessionStorage.getItem('last_click_time') || '0';
                    const loadTime = (performance.now() - pageLoadTime) / 1000;
                    
                    // Add hidden fields for behavior tracking
                    const fields = {
                        'has_mouse_movement': hasMouseMove,
                        'scroll_depth': scrollDepth,
                        'last_click_time': lastClickTime,
                        'page_load_time': loadTime.toString()
                    };
                    
                    for (const [name, value] of Object.entries(fields)) {
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = name;
                        input.value = value;
                        this.appendChild(input);
                    }
                });
            </script>
        </body>
        </html>
    ''', HONEYPOT_FIELD_NAME=HONEYPOT_FIELD_NAME, 
        HONEYPOT_FIELD_NAME_2=HONEYPOT_FIELD_NAME_2,
        HONEYPOT_FIELD_NAME_3=HONEYPOT_FIELD_NAME_3,
        fingerprint=f"fp-{random.randint(1000, 9999)}")

@app.route('/dashboard')
def dashboard():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return redirect('/login')
    
    # Check for session hijacking
    if AttackDetector.detect_session_hijacking(session_id, request):
        print(f"[DEBUG] Session hijacking detected for session {session_id}, marking as compromised and blocking IP {request.remote_addr}")
        sessions[session_id]['status'] = 'Compromised'
        PreventionSystem.block_ip(request.remote_addr)
        socketio.emit('update_sessions', sessions, namespace='/monitoring')
        return render_template_string('''
            <h1 style="color: red;">Security Alert</h1>
            <p>Your session has been terminated due to suspicious activity.</p>
            <p>Please <a href="/login">login again</a>.</p>
        '''),403
    
    # Update session activity
    sessions[session_id]['last_activity'] = time.time()
    
    # Check for honeypot field submissions
    honeypot_fields = ['admin_token', 'debug_mode', 'api_key']
    for field in honeypot_fields:
        if field in request.args:
            print(f"[DEBUG] Honeypot field '{field}' triggered by session {session_id}, marking as compromised and blocking IP {request.remote_addr}")
            # Mark session as compromised before blocking IP
            sessions[session_id]['status'] = 'Compromised'
            # Log the attack before blocking
            log_attack(
                attack_type="Dashboard Honeypot Triggered",
                ip=request.remote_addr,
                session_id=session_id,
                details=f"Honeypot field '{field}' accessed - IP Blocked",
                page='/dashboard'
            )
            PreventionSystem.block_ip(request.remote_addr)
            # Notify monitoring clients about session update
            socketio.emit('update_sessions', sessions, namespace='/monitoring')
            return render_template_string('''
                <h1 style="color: red;">Security Alert</h1>
                <p>Your session has been terminated due to suspicious activity.</p>
                <p>Please <a href="/login">login again</a>.</p>
            '''),403
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .welcome { background: #e8f4f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .menu a { display: inline-block; margin-right: 10px; padding: 8px 12px; background: #4CAF50; color: white; text-decoration: none; border-radius: 4px; }
                .session-info { margin-top: 20px; padding: 10px; background: #f0f0f0; border-radius: 4px; }
                .hidden-field { display: none; }
            </style>
        </head>
        <body>
            <div class="welcome">
                <h1>Welcome, {{ username }}!</h1>
                <p>You have successfully logged in to your account.</p>
            </div>
            
            <div class="menu">
                <a href="/profile">Profile</a>
                <a href="/settings">Settings</a>
                <a href="/logout">Logout</a>
            </div>
            
            <div class="session-info">
                <h3>Session Information</h3>
                <p><strong>Session ID:</strong> {{ session_id }}</p>
                <p><strong>IP Address:</strong> {{ ip }}</p>
                <p><strong>Status:</strong> <span style="color: green;">{{ status }}</span></p>
            </div>

            <!-- Hidden honeypot fields -->
            <div class="hidden-field">
                <a href="/dashboard?admin_token=123">Admin Panel</a>
                <a href="/dashboard?debug_mode=true">Debug Console</a>
                <a href="/dashboard?api_key=test">API Documentation</a>
            </div>

            <script>
                // Track user behavior
                let mouseMoved = false;
                let lastClickTime = 0;
                let maxScrollDepth = 0;
                let pageLoadTime = performance.now();
                let mouseMovementCount = 0;
                
                // Track mouse movement
                document.addEventListener('mousemove', function() {
                    mouseMoved = true;
                    mouseMovementCount++;
                    sessionStorage.setItem('has_mouse_movement', 'true');
                    sessionStorage.setItem('mouse_movement_count', mouseMovementCount.toString());
                });
                
                // Track clicks
                document.addEventListener('click', function() {
                    const now = performance.now();
                    const timeSinceLastClick = now - lastClickTime;
                    lastClickTime = now;
                    
                    if (timeSinceLastClick > 0 && timeSinceLastClick < 100) {
                        sessionStorage.setItem('last_click_time', timeSinceLastClick.toString());
                    }
                });
                
                // Track scrolling
                document.addEventListener('scroll', function() {
                    const scrollDepth = (window.scrollY + window.innerHeight) / document.documentElement.scrollHeight;
                    maxScrollDepth = Math.max(maxScrollDepth, scrollDepth);
                    sessionStorage.setItem('scroll_depth', maxScrollDepth.toString());
                });

                // Track time on page
                setInterval(function() {
                    const timeOnPage = (performance.now() - pageLoadTime) / 1000;
                    sessionStorage.setItem('time_on_page', timeOnPage.toString());
                }, 1000);
            </script>
        </body>
        </html>
    ''', username=sessions[session_id]['username'], 
       session_id=session_id[:8] + "...", 
       ip=request.remote_addr,
       status=sessions[session_id]['status'])

@app.route('/secret-admin-page')
def honeypot():
    # This is a honeypot route that should only be found by bots
    log_attack(
        attack_type="Honeypot Triggered",
        ip=request.remote_addr,
        details="Bot accessed hidden admin page"
    )
    return "Nothing to see here", 404

@app.route('/products')
def products():
    ip_status = PreventionSystem.check_ip_reputation(request.remote_addr)
    if ip_status == "blocked":
        return render_template_string('<h1 style="color: red;">Access Denied</h1>', 403)
    elif ip_status == "slowed":
        time.sleep(3)
    
    # Track request
    if request.remote_addr in ip_reputation:
        ip_reputation[request.remote_addr]['request_times'].append(time.time())
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Products</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
                .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; }
                .product-card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; }
                .product-card img { width: 100%; height: 200px; object-fit: cover; }
                .hidden-link { position: absolute; left: -9999px; }
                .hidden-field { display: none; }
            </style>
        </head>
        <body>
            <h1>Our Products</h1>
            
            <!-- Hidden honeypot links -->
            <div class="hidden-link">
                <a href="/admin/dashboard">Admin Dashboard</a>
                <a href="/internal/api">Internal API</a>
                <a href="/debug/console">Debug Console</a>
            </div>
            
            <!-- Hidden honeypot form -->
            <div class="hidden-field">
                <form id="honeypotForm" method="post" action="/api/subscribe">
                    <input type="email" name="email" value="">
                    <input type="text" name="token" value="">
                    <button type="submit">Subscribe</button>
                </form>
            </div>
            
            <div class="product-grid">
                <div class="product-card">
                    <img src="https://via.placeholder.com/300x200" alt="Product 1">
                    <h3>Product 1</h3>
                    <p>Description of product 1</p>
                    <button onclick="trackClick()">View Details</button>
                </div>
                <div class="product-card">
                    <img src="https://via.placeholder.com/300x200" alt="Product 2">
                    <h3>Product 2</h3>
                    <p>Description of product 2</p>
                    <button onclick="trackClick()">View Details</button>
                </div>
                <div class="product-card">
                    <img src="https://via.placeholder.com/300x200" alt="Product 3">
                    <h3>Product 3</h3>
                    <p>Description of product 3</p>
                    <button onclick="trackClick()">View Details</button>
                </div>
            </div>
            
            <script>
                // Track user behavior
                let mouseMoved = false;
                let lastClickTime = 0;
                let maxScrollDepth = 0;
                let pageLoadTime = performance.now();
                let interactionCount = 0;
                
                // Track mouse movement
                document.addEventListener('mousemove', function() {
                    mouseMoved = true;
                    sessionStorage.setItem('has_mouse_movement', 'true');
                });
                
                // Track clicks
                function trackClick() {
                    const now = performance.now();
                    const timeSinceLastClick = now - lastClickTime;
                    lastClickTime = now;
                    interactionCount++;
                    
                    if (timeSinceLastClick > 0 && timeSinceLastClick < 100) {
                        sessionStorage.setItem('last_click_time', timeSinceLastClick.toString());
                    }
                }
                
                // Track scrolling
                document.addEventListener('scroll', function() {
                    const scrollDepth = (window.scrollY + window.innerHeight) / document.documentElement.scrollHeight;
                    maxScrollDepth = Math.max(maxScrollDepth, scrollDepth);
                    sessionStorage.setItem('scroll_depth', maxScrollDepth.toString());
                });
                
                // Track page visibility
                document.addEventListener('visibilitychange', function() {
                    if (document.visibilityState === 'visible') {
                        sessionStorage.setItem('page_visible', 'true');
                    }
                });
                
                // Track form interactions
                document.getElementById('honeypotForm').addEventListener('submit', function(e) {
                    e.preventDefault();
                    sessionStorage.setItem('honeypot_triggered', 'true');
                });
                
                // Send behavior data periodically
                setInterval(function() {
                    const behaviorData = {
                        has_mouse_movement: sessionStorage.getItem('has_mouse_movement') || 'false',
                        scroll_depth: sessionStorage.getItem('scroll_depth') || '0',
                        last_click_time: sessionStorage.getItem('last_click_time') || '0',
                        page_load_time: ((performance.now() - pageLoadTime) / 1000).toString(),
                        interaction_count: interactionCount.toString(),
                        page_visible: sessionStorage.getItem('page_visible') || 'false',
                        honeypot_triggered: sessionStorage.getItem('honeypot_triggered') || 'false'
                    };
                    
                    // Send data to server
                    fetch('/api/track-behavior', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(behaviorData)
                    });
                }, 5000);
            </script>
        </body>
        </html>
    ''')

@app.route('/api/track-behavior', methods=['POST'])
def track_behavior():
    data = request.get_json()
    ip = request.remote_addr
    
    # Skip behavior checks for admin monitor page
    if request.referrer and '/admin/monitor' in request.referrer:
        return jsonify({'status': 'ok'})
    
    # Check for suspicious behavior
    if data.get('honeypot_triggered') == 'true':
        log_attack(
            attack_type="Honeypot Form Triggered",
            ip=ip,
            details="Bot interacted with hidden form"
        )
        PreventionSystem.block_ip(ip)
        return jsonify({'status': 'blocked'}), 403
    
    # Check for suspicious page load
    if float(data.get('page_load_time', 0)) < MIN_PAGE_LOAD_TIME:
        log_attack(
            attack_type="Suspicious Page Load",
            ip=ip,
            details=f"Page loaded too quickly: {data.get('page_load_time')}s"
        )
    
    return jsonify({'status': 'ok'})

# Monitoring system
@app.route('/admin/monitor')
def admin_monitor():
    # Removed IP check to make the page directly accessible
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Monitoring Dashboard</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.css">
            <style>
                .attack-log { max-height: 300px; overflow-y: auto; }
                .attack-entry { padding: 10px; border-bottom: 1px solid #eee; }
                .attack-entry.suspicious { background-color: #fff3cd; }
                .attack-entry.critical { background-color: #f8d7da; }
                .stat-card { border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .stat-card h3 { font-size: 1.2rem; margin-bottom: 10px; }
            </style>
        </head>
        <body>
            <div class="container-fluid mt-4">
                <h1 class="mb-4">Security Monitoring Dashboard</h1>
                
                <div class="row mb-4">
                    <div class="col-md-4">
                        <div class="stat-card bg-primary text-white">
                            <h3>Active Sessions</h3>
                            <h2 id="active-sessions">0</h2>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card bg-warning text-dark">
                            <h3>Attack Attempts</h3>
                            <h2 id="attack-count">0</h2>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card bg-danger text-white">
                            <h3>Blocked IPs</h3>
                            <h2 id="blocked-ips">0</h2>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header bg-dark text-white">
                                <h2 class="h5 mb-0">Attack Types Distribution</h2>
                            </div>
                            <div class="card-body">
                                <canvas id="attackChart" height="250"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header bg-dark text-white">
                                <h2 class="h5 mb-0">Recent Attacks</h2>
                            </div>
                            <div class="card-body attack-log" id="attack-log">
                                <!-- Attacks will appear here -->
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header bg-dark text-white">
                                <h2 class="h5 mb-0">Active Sessions</h2>
                            </div>
                            <div class="card-body">
                                <table class="table table-striped" id="sessions-table">
                                    <thead>
                                        <tr>
                                            <th>User</th>
                                            <th>Session ID</th>
                                            <th>IP Address</th>
                                            <th>Status</th>
                                            <th>Last Activity</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Sessions will appear here -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
            <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
            <script>
                const socket = io('/monitoring');
                let attackChart;
                
                // Initialize chart
                function initChart() {
                    const ctx = document.getElementById('attackChart').getContext('2d');
                    attackChart = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: [],
                            datasets: [{
                                data: [],
                                backgroundColor: [
                                    '#ff6384',
                                    '#36a2eb',
                                    '#ffce56',
                                    '#4bc0c0',
                                    '#9966ff'
                                ]
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'bottom'
                                }
                            }
                        }
                    });
                }
                
                // Update chart data
                function updateChart(data) {
                    const labels = Object.keys(data);
                    const values = Object.values(data);
                    
                    attackChart.data.labels = labels;
                    attackChart.data.datasets[0].data = values;
                    attackChart.update();
                }
                
                // Add attack to log
                function addAttackLog(attack) {
                    const logElement = document.getElementById('attack-log');
                    const entry = document.createElement('div');
                    entry.className = 'attack-entry ' + (attack.type.includes('Attempt') ? 'suspicious' : 'critical');
                    
                    entry.innerHTML = `
                        <strong>${attack.timestamp}</strong> - ${attack.type}
                        <div><small>IP: ${attack.ip} | ${attack.details}</small></div>
                    `;
                    
                    logElement.insertBefore(entry, logElement.firstChild);
                    document.getElementById('attack-count').textContent = parseInt(document.getElementById('attack-count').textContent) + 1;
                }
                
                // Add action to log
                function addActionLog(action) {
                    const logElement = document.getElementById('attack-log');
                    const entry = document.createElement('div');
                    entry.className = 'attack-entry';
                    
                    entry.innerHTML = `
                        <strong>${action.timestamp}</strong> - ACTION: ${action.action}
                        <div><small>Source: ${action.source}</small></div>
                    `;
                    
                    logElement.insertBefore(entry, logElement.firstChild);
                }
                
                // Update sessions table
                function updateSessions(sessions) {
                    const tableBody = document.querySelector('#sessions-table tbody');
                    tableBody.innerHTML = '';
                    
                    Object.entries(sessions).forEach(([id, session]) => {
                        const row = document.createElement('tr');
                        const lastActive = new Date(session.last_activity * 1000).toLocaleTimeString();
                        
                        row.innerHTML = `
                            <td>${session.username || 'Unknown'}</td>
                            <td>${id.substring(0, 8)}...</td>
                            <td>${session.ip}</td>
                            <td><span class="badge ${session.status === 'Normal' ? 'bg-success' : 'bg-danger'}">${session.status}</span></td>
                            <td>${lastActive}</td>
                            <td>
                                <button class="btn btn-sm btn-warning" onclick="terminateSession('${id}')">Terminate</button>
                            </td>
                        `;
                        
                        tableBody.appendChild(row);
                    });
                    
                    document.getElementById('active-sessions').textContent = Object.keys(sessions).length;
                }
                
                // Update blocked IPs count
                function updateBlockedIPs(count) {
                    document.getElementById('blocked-ips').textContent = count;
                }
                
                // Socket event handlers
                socket.on('connect', () => {
                    console.log('Connected to monitoring server');
                    // Request initial data
                    socket.emit('get_initial_data');
                });
                
                socket.on('initial_data', (data) => {
                    updateChart(data.attack_types);
                    updateSessions(data.sessions);
                    updateBlockedIPs(data.blocked_ips);
                    document.getElementById('attack-count').textContent = data.total_attacks;
                    
                    // Display initial recent attacks
                    data.recent_attacks.forEach(attack => {
                        addAttackLog(attack);
                    });
                });
                
                socket.on('new_attack', (attack) => {
                    addAttackLog(attack);
                });
                
                socket.on('new_action', (action) => {
                    addActionLog(action);
                });
                
                socket.on('update_sessions', (sessions) => {
                    updateSessions(sessions);
                });
                
                socket.on('update_stats', (stats) => {
                    updateChart(stats.attack_types);
                    updateBlockedIPs(stats.blocked_ips);
                });
                
                // Helper functions
                function terminateSession(sessionId) {
                    socket.emit('terminate_session', { session_id: sessionId });
                }
                
                // Initialize
                document.addEventListener('DOMContentLoaded', () => {
                    initChart();
                });
            </script>
        </body>
        </html>
    ''')

# WebSocket handlers for real-time monitoring
@socketio.on('connect', namespace='/monitoring')
def handle_monitoring_connect(auth=None):
    monitoring_clients.add(request.sid)
    print(f"Monitoring client connected: {request.sid}")
    
    # Send initial data
    attack_types = defaultdict(int)
    for attack in attack_logs:
        attack_types[attack['type']] += 1
    
    emit('initial_data', {
        'sessions': sessions,
        'attack_types': attack_types,
        'total_attacks': len(attack_logs),
        'blocked_ips': len([ip for ip, rep in ip_reputation.items() if rep.get('blocked', False)]),
        'recent_attacks': recent_attacks[-50:]  # Send last 50 attacks
    })

@socketio.on('disconnect', namespace='/monitoring')
def handle_monitoring_disconnect():
    monitoring_clients.discard(request.sid)
    print(f"Monitoring client disconnected: {request.sid}")

@socketio.on('terminate_session', namespace='/monitoring')
def handle_terminate_session(data):
    session_id = data['session_id']
    if session_id in sessions:
        del sessions[session_id]
        log_action(f"Terminated session {session_id[:8]}...", "Admin")
        emit('update_sessions', sessions, namespace='/monitoring')

# Background task to update stats periodically
def background_stats_update():
    while True:
        socketio.sleep(5)
        
        # Calculate attack type distribution
        attack_types = defaultdict(int)
        for attack in attack_logs:
            attack_types[attack['type']] += 1
        
        # Count blocked IPs
        blocked_ips = len([ip for ip, rep in ip_reputation.items() if rep.get('blocked', False)])
        
        socketio.emit('update_stats', {
            'attack_types': attack_types,
            'blocked_ips': blocked_ips
        }, namespace='/monitoring')

# Start background thread
socketio.start_background_task(background_stats_update)

if __name__ == '__main__':
    print("Starting application...")
    print(f"Admin monitoring available at: http://localhost:5010/admin/monitor")
    socketio.run(app, debug=True, host='0.0.0.0', port=5010)





