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
executor = ThreadPoolExecutor(max_workers=10)
client = None
uvloop.install()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Scanner instances lock
scanner_lock = threading.Lock()
active_scanners: Dict[str, AdvancedBurpScanner] = {}

def get_scanner(scanner_id: str, config: Optional[Dict] = None) -> AdvancedBurpScanner:
    """Get or create a scanner instance with thread safety"""
    global active_scanners
    with scanner_lock:
        if scanner_id not in active_scanners:
            if not config:
                config = {
                    'general': {
                        'threads': 10,
                        'rate_limit': 0.1,
                        'timeout': 10
                    },
                    'scan_types': {
                        'sqli': True,
                        'xss': True,
                        'idor': True,
                        'ssrf': True
                    }
                }
            active_scanners[scanner_id] = AdvancedBurpScanner("", config)
        return active_scanners[scanner_id]

@app.route('/scanner/start', methods=['POST'])
def start_scan():
    """Start a new scan with optional configuration"""
    try:
        data = request.json
        if not data or 'url' not in data:
            return jsonify({"error": "Missing 'url' in payload"}), 400
        
        scanner_id = data.get('scanner_id', f"scan_{int(time.time())}")
        config = data.get('config', {})
        
        scanner = get_scanner(scanner_id, config)
        scanner.base_url = data['url']
        
        # Run scan in background thread
        def run_scan():
            try:
                scanner.run_scan()
            except Exception as e:
                logger.error(f"Scan failed: {str(e)}")
        
        executor.submit(run_scan)
        
        return jsonify({
            "scanner_id": scanner_id,
            "status": "scan_started",
            "config": config
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scanner/status/<scanner_id>', methods=['GET'])
def scan_status(scanner_id):
    """Get scan status and results"""
    try:
        scanner = get_scanner(scanner_id)
        
        return jsonify({
            "scanner_id": scanner_id,
            "status": "running" if not scanner.vulnerabilities else "completed",
            "vulnerabilities_found": len(scanner.vulnerabilities),
            "pages_crawled": len(scanner.visited_urls),
            "last_10_vulnerabilities": scanner.vulnerabilities[-10:] if scanner.vulnerabilities else []
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/scanner/results/<scanner_id>', methods=['GET'])
def scan_results(scanner_id):
    """Get full scan results"""
    try:
        scanner = get_scanner(scanner_id)
        
        if not scanner.vulnerabilities:
            return jsonify({"error": "Scan not completed or no vulnerabilities found"}), 404
            
        return jsonify({
            "scanner_id": scanner_id,
            "vulnerabilities": scanner.vulnerabilities,
            "metadata": {
                "pages_crawled": len(scanner.visited_urls),
                "api_endpoints": len(scanner.api_endpoints),
                "scan_duration": f"{(time.time() - scanner.start_time):.2f}s" if hasattr(scanner, 'start_time') else "unknown"
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/scanner/stop/<scanner_id>', methods=['POST'])
def stop_scan(scanner_id):
    """Stop a running scan"""
    global active_scanners
    try:
        with scanner_lock:
            if scanner_id in active_scanners:
                del active_scanners[scanner_id]
        return jsonify({"status": "scan_stopped", "scanner_id": scanner_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


browser_lock = threading.Lock()
browser_instance = None

def get_browser():
    """Get or create a browser instance with thread safety"""
    global browser_instance
    with browser_lock:
        if browser_instance is None:
            browser_instance = TextBasedBrowser(
                headless=True,  # Set to False for debugging
                user_data_dir="./browser_data",
                proxy=None  # Add your proxy here if needed
            )
        return browser_instance

@app.route('/browser/execute', methods=['POST'])
def execute_browser_commands():
    """Endpoint for executing browser commands"""
    try:
        data = request.json
        
        # Validate input
        if not data or 'instructions' not in data:
            return jsonify({"error": "Missing 'instructions' in payload"}), 400
        
        # Get browser instance
        browser = get_browser()
        
        # Execute instructions
        results = browser.execute_ai_instructions(data['instructions'])
        
        # Return both the results and current page state
        return jsonify({
            "results": results,
            "current_state": browser.current_page_text,
            "interactive_elements": [
                elem["description"] for elem in browser.interactive_elements
            ]
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/browser/reset', methods=['POST'])
def reset_browser():
    """Reset the browser instance"""
    global browser_instance
    try:
        with browser_lock:
            if browser_instance:
                browser_instance.close()
                browser_instance = None
        return jsonify({"status": "Browser reset successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.teardown_appcontext
def shutdown_browser(exception=None):
    """Clean up browser when app shuts down"""
    global browser_instance
    with browser_lock:
        if browser_instance:
            browser_instance.close()
            browser_instance = None


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
