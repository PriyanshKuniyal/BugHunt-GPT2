# utils/burp_repeater.py
import httpx
from flask import Blueprint, request, jsonify
import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
import uvloop
import threading

repeater_bp = Blueprint('repeater', __name__)
client = None
executor = ThreadPoolExecutor(max_workers=4)
event_loop = None

def init_app(app):
    """Initialize the repeater with the Flask app"""
    app.register_blueprint(repeater_bp, url_prefix='/utils')
    
    # Create event loop in a separate thread
    global event_loop
    event_loop = asyncio.new_event_loop()
    
    def run_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()
    
    threading.Thread(target=run_loop, args=(event_loop,), daemon=True).start()
    
    # Initialize client
    async def create_client():
        global client
        uvloop.install()
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
        timeout = httpx.Timeout(10.0, connect=5.0)
        client = httpx.AsyncClient(limits=limits, timeout=timeout, http2=True)
    
    asyncio.run_coroutine_threadsafe(create_client(), event_loop).result()
    
    # Cleanup when app closes
    @app.teardown_appcontext
    def shutdown(exception=None):
        if client:
            async def close_client():
                try:
                    await client.aclose()
                except:
                    pass  # Ignore errors during shutdown
            
            asyncio.run_coroutine_threadsafe(close_client(), event_loop).result()

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
    
    future = executor.submit(
        asyncio.run_coroutine_threadsafe,
        send_async_request(url, req_data, headers, method),
        event_loop
    ).result()
    
    try:
        result = future.result(timeout=10)
        if not result.get('success', False):
            return jsonify(result), 500
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
