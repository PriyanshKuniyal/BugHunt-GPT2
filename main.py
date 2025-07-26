from flask import Flask, request, jsonify
from utils.burp_proxy import capture_data  # Correct relative import
import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
import uvloop
from utils.burp_repeater import init_app

app = Flask(__name__)

# Initialize the repeater
init_app(app)

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

# Thread pool for sync-to-async bridge
executor = ThreadPoolExecutor(max_workers=4)
client=None
uvloop.install()
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
