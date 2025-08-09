import httpx
from playwright.async_api import async_playwright
from urllib.parse import urlparse
import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def capture_data(url: str) -> dict:
    """Enhanced version with DNS validation and retry logic"""
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    result = {
        "server_response": None,
        "browser_requests": [],
        "error": None
    }

    # 1. First validate DNS resolution
    try:
        hostname = urlparse(url).netloc.split(':')[0]
        socket.gethostbyname(hostname)
    except socket.gaierror as e:
        error_msg = f"DNS resolution failed for {hostname}: {str(e)}"
        logger.error(error_msg)
        result["error"] = error_msg
        return result

    # 2. Server request with retry
    async with httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_connections=5),
        transport=httpx.AsyncHTTPTransport(retries=3)
    ) as client:
        try:
            resp = await client.get(
                url,
                follow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                }
            )
            try:
                content_sample = resp.text[:2000] + "..." if len(resp.text) > 2000 else resp.text
                result["server_response"] = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                    "content_sample": resp.text[:2000] + "..." if len(resp.text) > 2000 else resp.text
                }
            except Exception as e:
                # log and continue with raw or empty content
                logger.warning(f"Decompression or decoding failed: {e}")
                content_sample = "<decompression error>"
                result["server_response"] = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                    "content_sample": content_sample
                }

        except Exception as e:
            error_msg = f"Server request failed: {str(e)}"
            logger.error(error_msg)
            result["error"] = error_msg
            return result

    # 3. Browser capture (only if server request succeeded)
    if result["server_response"]:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    timeout=30000,
                    args=[
                        '--disable-gpu',
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--dns-prefetch-disable'  # Important for DNS stability
                    ]
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                )
                
                page = await context.new_page()
                
                requests = []
                def log_request(request):
                    if urlparse(url).netloc in request.url:
                        requests.append({
                            "method": request.method,
                            "url": request.url,
                            "headers": dict(request.headers)
                        })
                
                page.on("request", log_request)
                
                try:
                    await page.goto(url, wait_until="networkidle", timeout=45000)
                    result["browser_requests"] = requests
                except Exception as e:
                    logger.warning(f"Browser navigation warning: {str(e)}")
                finally:
                    await browser.close()
                    
        except Exception as e:
            logger.error(f"Playwright failed: {str(e)}")
            # Don't overwrite server response if browser fails

    return result
