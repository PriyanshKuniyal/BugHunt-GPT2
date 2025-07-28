from flask import Flask, request, jsonify
from utils.burp_proxy import capture_data
from utils.burp_repeater import init_app
from utils.burp_intruder import intruder_engine, AttackType
from utils.burp_sequencer import sequencer_engine
import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
import uvloop

app = Flask(__name__)

# Initialize the repeater
init_app(app)

# Thread pool for sync-to-async bridge
executor = ThreadPoolExecutor(max_workers=4)
client = None
uvloop.install()

@app.route("/intruder/attack", methods=["POST"])
async def intruder_attack():
    data = request.json
    try:
        result = await intruder_engine.attack(
            base_request=data["base_request"],
            attack_type=data["attack_type"],
            payload_sets=data["payload_sets"],
            payload_positions=data["payload_positions"],
            max_requests=data.get("max_requests", 1000),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/sequencer/analyze', methods=['POST'])
async def sequencer_analysis():
    data = request.json
    print("[DEBUG] Incoming Data:", data)  # Add this line

    try:
        required_fields = ['base_request', 'token_locations']
        if not all(field in data for field in required_fields):
            return jsonify({"error": f"Missing required fields: {required_fields}"}), 400

        result = await sequencer_engine.analyze(
            base_request=data["base_request"],
            token_locations=data["token_locations"],
            sample_size=data.get("sample_size", 500),
            concurrency=data.get("concurrency", 50)
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/burp_capture', methods=['GET', 'POST'])
async def burp_capture():
    url = request.json.get('url') if request.method == 'POST' else request.args.get('url')
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    try:
        data = await capture_data(url)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/repeater', methods=['POST'])
def repeater():
    """Main endpoint - bridges sync Flask with async httpx"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    
    # Validate input (minimal validation for speed)
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url in payload'}), 400
    
    # Extract parameters with defaults
    url = data['url']
    req_data = data.get('request', {})
    headers = data.get('headers', {})
    method = data.get('method', 'POST').upper()
    
    # Run async function from sync context
    future = executor.submit(
        asyncio.run,
        send_async_request(url, req_data, headers, method)
    )
    
    try:
        result = future.result(timeout=10)
        if not result.get('success', False):
            return jsonify(result), 500
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
