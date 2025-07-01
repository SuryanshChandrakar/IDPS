# server.py level 34 ddos
import eventlet
eventlet.monkey_patch()

from flask import Flask, send_from_directory
from flask_socketio import SocketIO
import redis
import threading
import time
import os
app = Flask(__name__, static_folder="public")
socketio = SocketIO(app, 
                   cors_allowed_origins='*',
                   async_mode='eventlet',
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=1e8)

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

ATTACK_TYPES = ['SYN', 'UDP', 'ICMP', 'FRAG', 'TCP', 'Smurf']
class RedisStreamer:
    def __init__(self):
        self.emission_delay = 0.1  # 100ms delay between emissions

    def stream_data(self):
        while True:
            try:
                for atype in ATTACK_TYPES:
                    key = f'graph_data:{atype}'
                    while True:
                        entry = r.lpop(key)
                        if entry is None:
                            break
                        try:
                            _, count = entry.split(',')
                            print(f"[{atype}] Sending: count={count}")
                            socketio.emit("attack_data", {
                                "type": atype,
                                "count": int(count)
                            })
                            time.sleep(self.emission_delay)  # Add delay between emissions
                        except Exception as e:
                            print(f"[{atype}] Error parsing entry '{entry}': {e}")
                            continue
                time.sleep(0.1)  # Small delay between attack types
            except Exception as e:
                print(f"Error in stream_data: {e}")
                time.sleep(5)  # Wait before retrying

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.getcwd(), 'favicon.ico')

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

@socketio.on_error()
def error_handler(e):
    print(f"Socket.IO error: {e}")

if __name__ == '__main__':
    streamer = RedisStreamer()
    threading.Thread(target=streamer.stream_data, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)







