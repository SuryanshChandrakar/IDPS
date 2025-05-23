# backend.py
# level 7 HTTPS flooding
import eventlet
eventlet.monkey_patch()
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
from threading import Thread
from datetime import datetime
import redis
import time
import psutil
import logging
import os

app = Flask(__name__, 
            template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# === Config ===
MAX_REQUESTS_PER_SECOND = 10
BLACKLIST_DURATION = 300  # seconds

# === Redis and Logging ===
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
logging.basicConfig(filename="security_logs.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# === Dashboard ===
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return root_handler()
    return render_template('dashboard.html')

@app.route('/admin/monitoring')
def monitoring_dashboard():
    return render_template('dashboard.html')

@app.route('/api/logs')
def get_logs():
    logs = redis_client.lrange("request_logs", 0, 20)
    return jsonify([eval(log) for log in logs])

@app.route('/api/traffic-history')
def get_traffic_history():
    return jsonify(redis_client.hgetall("request_history_per_minute"))

@app.route('/api/blacklist', methods=['POST'])
def blacklist_ip():
    data = request.json
    ip = data.get('ip')
    if ip:
        redis_client.sadd("blocked_ips", ip)
        redis_client.expire("blocked_ips", BLACKLIST_DURATION)
        logging.info(f"IP {ip} manually blacklisted")
        socketio.emit("update_data", get_dashboard_data())
        return jsonify({"message": f"{ip} blacklisted!"})
    return jsonify({"error": "Missing IP"}), 400

@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    if redis_client.srem("blocked_ips", ip):
        logging.info(f"IP {ip} unblocked")
        socketio.emit("update_data", get_dashboard_data())
        return jsonify({"message": f"{ip} unblocked"})
    return jsonify({"error": "IP not in blacklist"}), 404

# === Main Endpoint (Handles real traffic) ===
@app.route('/api/request', methods=['GET', 'POST'])
def root_handler():
    ip = request.remote_addr
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    if redis_client.sismember("blocked_ips", ip):
        return jsonify({"error": "Your IP is blacklisted."}), 403

    # Rate limiting
    redis_key = f"request_rate:{ip}"
    redis_client.incr(redis_key)
    redis_client.expire(redis_key, 2)

    if int(redis_client.get(redis_key) or 0) > MAX_REQUESTS_PER_SECOND:
        redis_client.sadd("blocked_ips", ip)
        redis_client.expire("blocked_ips", BLACKLIST_DURATION)
        logging.info(f"IP {ip} auto-blacklisted")
        socketio.emit("update_data", get_dashboard_data())
        return jsonify({"error": "Rate limit exceeded, blacklisted"}), 429

    # Log allowed request
    log_entry = {"ip": ip, "status": "allowed", "timestamp": timestamp}
    redis_client.lpush("request_logs", str(log_entry))
    redis_client.ltrim("request_logs", 0, 19)

    # Track traffic
    current_minute = datetime.now().strftime("%Y-%m-%d %H:%M")
    redis_client.hincrby("request_history_per_minute", current_minute, 1)
    socketio.emit("update_data", get_dashboard_data())

    # Return response (mock or echo)
    data = request.get_json(silent=True)
    return jsonify({
        "message": "Request received and processed",
        "ip": ip,
        "data": data
    }), 200

# === Dashboard Push Thread ===
def get_dashboard_data():
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent,
        "active_requests": len(redis_client.lrange("request_logs", 0, -1)),
        "request_logs": [eval(log) for log in redis_client.lrange("request_logs", 0, 20)],
        "blocked_ips": list(redis_client.smembers("blocked_ips")),
        "traffic_history": redis_client.hgetall("request_history_per_minute")
    }

def monitor_system():
    while True:
        time.sleep(1)
        socketio.emit("update_data", get_dashboard_data())

Thread(target=monitor_system, daemon=True).start()

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5008, debug=True)
