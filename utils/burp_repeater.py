import httpx
from flask import Flask, request, jsonify
import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
import uvloop

app = Flask(__name__)
client = None
uvloop.install()  # Use ultra-fast uvloop for asyncio

# Initialize the async client at startup
@app.before_first_request
async def startup():
    global client
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
    timeout = httpx.Timeout(10.0, connect=5.0)
    client = httpx.AsyncClient(limits=limits, timeout=timeout, http2=True)

# Cleanup on shutdown
@app.teardown_appcontext
async def shutdown(exception=None):
    if client:
        await client.aclose()

async def send_async_request(url: str, req_data: dict, headers: dict = None, method: str = 'POST'):
    """Ultra-optimized async request handler"""
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
