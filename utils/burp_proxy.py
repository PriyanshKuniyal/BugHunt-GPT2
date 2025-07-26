import asyncio
from urllib.parse import urlparse
from typing import Dict, List, Optional
import httpx
from playwright.async_api import async_playwright
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def capture_data(url: str) -> Dict[str, any]:
    """
    Capture server response and browser requests for a given URL
    
    Args:
        url: Target URL to analyze (must include http:// or https://)
    
    Returns:
        Dictionary containing:
        - server_response: Raw HTTP response from direct request
        - browser_requests: List of requests made by browser
        - error: Optional error message if any step failed
    """
    # Validate and normalize URL
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    target_host = urlparse(url).netloc
    result = {
        "server_response": None,
        "browser_requests": [],
        "error": None
    }

    # 1. Capture direct server response
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(
                url,
                follow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                }
            )
            result["server_response"] = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "final_url": str(resp.url),
                "response_time_ms": resp.elapsed.microseconds / 1000,
                "content_sample": resp.text[:2000] + "..." if len(resp.text) > 2000 else resp.text
            }
        except Exception as e:
            logger.error(f"Server request failed: {str(e)}")
            result["error"] = f"Server request failed: {str(e)}"
            return result

    # 2. Capture browser activity
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                timeout=30000,
                args=[
                    '--disable-gpu',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--single-process'
                ]
            )
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                viewport={'width': 1280, 'height': 720},
                java_script_enabled=True
            )
            
            # Enable request interception
            await context.route('**/*', lambda route: route.continue_())
            
            page = await context.new_page()
            
            # Store requests
            requests = []
            
            def log_request(request):
                try:
                    if target_host in request.url:
                        requests.append({
                            "method": request.method,
                            "url": request.url,
                            "headers": dict(request.headers),
                            "resource_type": request.resource_type,
                            "timestamp": request.timestamp
                        })
                except Exception as e:
                    logger.warning(f"Failed to log request: {str(e)}")
            
            page.on("request", log_request)
            
            try:
                await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=45000,
                    referer=None
                )
                result["browser_requests"] = requests
            except Exception as e:
                logger.error(f"Browser navigation failed: {str(e)}")
                result["error"] = f"Browser navigation failed: {str(e)}"
            finally:
                await context.close()
                await browser.close()
                
    except Exception as e:
        logger.error(f"Playwright failed: {str(e)}")
        result["error"] = f"Playwright failed: {str(e)}"
    
    # Redact sensitive headers
    for request in result["browser_requests"]:
        for header in ['cookie', 'authorization', 'set-cookie']:
            if header in request["headers"]:
                request["headers"][header] = "[REDACTED]"
    
    return result
