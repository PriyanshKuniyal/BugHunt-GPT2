from flask import Flask, request, jsonify
from utils.burp_proxy import capture_data  # Correct relative import
import asyncio
import os

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
