import asyncio
import re
from itertools import product
from typing import List, Dict, Optional, Tuple, Union
import httpx
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackType:
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"

class PayloadGenerator:
    """Generates payloads efficiently with lazy evaluation"""
    @staticmethod
    def generate(payload_config: Dict) -> List[str]:
        payload_type = payload_config["type"]
        if payload_type == "wordlist":
            return payload_config["data"]
        elif payload_type == "range":
            start, end, step = payload_config["start"], payload_config["end"], payload_config.get("step", 1)
            return [str(i) for i in range(start, end, step)]
        elif payload_type == "bruteforce":
            charset = payload_config["charset"]
            min_len, max_len = payload_config["min_len"], payload_config["max_len"]
            return list(generate_bruteforce(charset, min_len, max_len))
        raise ValueError(f"Unsupported payload type: {payload_type}")

def generate_bruteforce(charset: str, min_len: int, max_len: int):
    """Lazy brute-force generator to avoid memory overload"""
    from itertools import product
    for length in range(min_len, max_len + 1):
        yield from (''.join(p) for p in product(charset, repeat=length)

class IntruderEngine:
    """Core Intruder engine with async HTTP, deduplication, and vulnerability detection"""
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(max_connections=100),
            follow_redirects=True
        )

    async def attack(
        self,
        base_request: Dict,
        attack_type: str,
        payload_sets: List[Dict],
        payload_positions: List[str],
        max_requests: int = 1000,
    ) -> Dict:
        # Generate payload combinations
        payload_combinations = self._generate_combinations(attack_type, payload_sets)
        
        # Execute requests with rate limiting
        semaphore = asyncio.Semaphore(50)  # Limit concurrent requests
        tasks = []
        for combo in payload_combinations[:max_requests]:
            modified_request = self._replace_payloads(base_request.copy(), payload_positions, combo)
            tasks.append(
                self._execute_request_with_semaphore(semaphore, modified_request, combo)
            )
        
        # Process responses
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return self._analyze_responses(responses)

    async def _execute_request_with_semaphore(self, semaphore, request, payload):
        async with semaphore:
            return await self._send_request(request, payload)

    def _generate_combinations(self, attack_type: str, payload_sets: List[Dict]) -> List[Tuple]:
        """Generate payload combinations based on attack type"""
        payloads = [PayloadGenerator.generate(config) for config in payload_sets]
        if attack_type == AttackType.SNIPER:
            return [(p,) for p in payloads[0]]
        elif attack_type == AttackType.CLUSTER_BOMB:
            return list(product(*payloads))
        elif attack_type == AttackType.PITCHFORK:
            return list(zip(*payloads))
        raise ValueError(f"Unsupported attack type: {attack_type}")

    def _replace_payloads(self, request: Dict, positions: List[str], payloads: Tuple) -> Dict:
        """Replace §0§, §1§ with actual payloads"""
        for i, pos in enumerate(positions):
            if "url" in request:
                request["url"] = request["url"].replace(f"§{i}§", str(payloads[i]))
            if "body" in request:
                request["body"] = request["body"].replace(f"§{i}§", str(payloads[i]))
            if "headers" in request:
                for header, value in request["headers"].items():
                    request["headers"][header] = value.replace(f"§{i}§", str(payloads[i]))
        return request

    async def _send_request(self, request: Dict, payload: Tuple) -> Tuple[Union[httpx.Response, Exception], Tuple]:
        """Send an async HTTP request"""
        try:
            resp = await self.client.request(
                method=request["method"],
                url=request["url"],
                headers=request.get("headers", {}),
                data=request.get("body"),
            )
            return resp, payload
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return e, payload

    def _analyze_responses(self, responses: List) -> Dict:
        """Group responses and detect vulnerabilities"""
        unique_responses = defaultdict(list)
        anomaly_stats = {
            "sqli": 0,
            "xss": 0,
            "error_responses": 0
        }

        for resp, payload in responses:
            if isinstance(resp, Exception):
                continue
            
            # Normalize response for deduplication
            stable_text = self._normalize_response(resp.text)
            response_key = f"{resp.status_code}|||{len(resp.text)}|||{stable_text[:200]}"  # Store snippet
            
            # Detect anomalies
            anomalies = self._detect_anomalies(resp, payload)
            if anomalies["is_sqli"]:
                anomaly_stats["sqli"] += 1
            if anomalies["is_xss"]:
                anomaly_stats["xss"] += 1
            if resp.status_code >= 400:
                anomaly_stats["error_responses"] += 1

            unique_responses[response_key].append({
                "payload": payload,
                "anomalies": anomalies
            })

        # Format final output
        results = []
        for key, payload_data in unique_responses.items():
            status_code, length, body_snippet = key.split('|||')
            results.append({
                "count": len(payload_data),
                "payloads": [item["payload"] for item in payload_data],
                "status_code": int(status_code),
                "response_length": int(length),
                "response_snippet": body_snippet,
                "sample_anomalies": payload_data[0]["anomalies"]  # Show from first occurrence
            })

        return {
            "results": results,
            "stats": {
                "total_requests": len(responses),
                "unique_responses": len(unique_responses),
                **anomaly_stats
            }
        }

    def _normalize_response(self, text: str) -> str:
        """Normalize dynamic content for better deduplication"""
        text = re.sub(r'\d+', '[NUM]', text)          # Replace numbers
        text = re.sub(r'[0-9a-f]{32}', '[HASH]', text)  # Replace hashes
        return text

    def _detect_anomalies(self, response: httpx.Response, payload: Tuple) -> Dict:
        """Detect potential vulnerabilities in response"""
        text = response.text.lower()
        payload_str = str(payload).lower()
        
        return {
            "is_sqli": any(
                term in text for term in ["error", "syntax", "mysql", "sql"]
            ) and ("'" in payload_str or "select" in payload_str),
            "is_xss": (
                any(tag in payload_str for tag in ["<script>", "onerror="]) 
                and payload_str in text
            ),
            "is_error": response.status_code >= 400
        }

# Singleton for reuse
intruder_engine = IntruderEngine()
