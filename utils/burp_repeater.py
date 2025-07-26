# utils/burp_repeater.py
import httpx
from flask import Blueprint, request, jsonify
import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
import uvloop

repeater_bp = Blueprint('repeater', __name__)
client = None
executor = ThreadPoolExecutor(max_workers=4)

def init_app(app):
    """Initialize the repeater with the Flask app"""
    app.register_blueprint(repeater_bp, url_prefix='/utils')
    
    # Initialize client when app starts
    with app.app_context():
        global client
        uvloop.install()
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
        timeout = httpx.Timeout(10.0, connect=5.0)
        client = httpx.AsyncClient(limits=limits, timeout=timeout, http2=True)
    
    # Cleanup when app closes
    @app.teardown_appcontext
    async def shutdown(exception=None):
        if client:
            await client.aclose()

async def send_async_request(url: str, req_data: dict, headers: dict = None, method: str = 'POST'):
    """Async request handler"""
    try:
        start = time.perf_counter()
        req_headers = headers or {}
        req_headers.setdefault('Content-Type', 'application/json')
        req_headers.setdefault('Accept', 'application/json')
        
        if method.upper() == 'GET':
            response = await client.get(url, params=req_data, headers=req_headers)
        else:
            response = await client.post(url, json=req_data, headers=req_headers)
        
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        try:
            resp_data = response.json()
        except json.JSONDecodeError:
            resp_data = response.text
            
        return {
            'status': response.status_code,
            'response': resp_data,
            'headers': dict(response.headers),
            'time_elapsed': round(elapsed_ms, 2),
            'success': True
        }
    except Exception as e:
        return {
            'error': str(e),
            'success': False
        }

@repeater_bp.route('/repeater', methods=['POST'])
def repeater():
    """Main endpoint"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url in payload'}), 400
    
    url = data['url']
    req_data = data.get('request', {})
    headers = data.get('headers', {})
    method = data.get('method', 'POST').upper()
    
    future = executor.submit(asyncio.run, send_async_request(url, req_data, headers, method))
    
    try:
        result = future.result(timeout=10)
        if not result.get('success', False):
            return jsonify(result), 500
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
