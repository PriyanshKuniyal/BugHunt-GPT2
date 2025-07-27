import asyncio
import re
from itertools import product
from typing import List, Dict, Optional, Tuple, Union
import httpx
from collections import defaultdict
import logging
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AttackType:
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"

@dataclass
class PayloadConfig:
    type: str  # "wordlist", "range", "bruteforce"
    data: Optional[List[str]] = None
    start: Optional[int] = None
    end: Optional[int] = None
    step: Optional[int] = 1
    charset: Optional[str] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None

class PayloadGenerator:
    """Optimized payload generation with lazy evaluation"""
    @staticmethod
    def generate(config: PayloadConfig) -> List[str]:
        if config.type == "wordlist":
            return config.data or []
        elif config.type == "range":
            return [str(i) for i in range(config.start, config.end, config.step)]
        elif config.type == "bruteforce":
            return list(PayloadGenerator._generate_bruteforce(
                config.charset, config.min_len, config.max_len
            ))
        raise ValueError(f"Unsupported payload type: {config.type}")

    @staticmethod
    def _generate_bruteforce(charset: str, min_len: int, max_len: int):
        """Memory-efficient brute-force generator"""
        from itertools import product
        for length in range(min_len, max_len + 1):
            yield from (''.join(p) for p in product(charset, repeat=length))

class IntruderEngine:
    """High-performance intruder engine with vulnerability analysis"""
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_connections=200),
            follow_redirects=True,
            http2=True
        )

    async def attack(
        self,
        base_request: Dict,
        attack_type: str,
        payload_sets: List[Dict],
        payload_positions: List[str],
        max_requests: int = 1000,
        concurrency: int = 100
    ) -> Dict:
        try:
            # Validate input
            self._validate_request(base_request)
            
            # Generate payloads
            configs = [PayloadConfig(**ps) for ps in payload_sets]
            payload_combinations = self._generate_combinations(attack_type, configs)
            
            # Execute attack
            semaphore = asyncio.Semaphore(concurrency)
            tasks = [
                self._execute_request(
                    semaphore,
                    self._replace_payloads(base_request.copy(), payload_positions, combo),
                    combo
                )
                for combo in payload_combinations[:max_requests]
            ]
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            return self._analyze_results(responses)
        
        except Exception as e:
            logger.error(f"Attack failed: {str(e)}")
            return {"error": str(e)}

    def _validate_request(self, request: Dict):
        """Validate HTTP request structure"""
        required = {"method", "url"}
        if not all(k in request for k in required):
            raise ValueError(f"Request missing required fields: {required}")

    def _generate_combinations(self, attack_type: str, payload_sets: List[PayloadConfig]) -> List[Tuple]:
        """Generate payload combinations based on attack type"""
        payloads = [PayloadGenerator.generate(c) for c in payload_sets]
        
        if attack_type == AttackType.SNIPER:
            return [(p,) for p in payloads[0]]
        elif attack_type == AttackType.CLUSTER_BOMB:
            return list(product(*payloads))
        elif attack_type == AttackType.PITCHFORK:
            return list(zip(*payloads))
        raise ValueError(f"Unsupported attack type: {attack_type}")

    def _replace_payloads(self, request: Dict, positions: List[str], payloads: Tuple) -> Dict:
        """Replace payload markers (§0§) in request components"""
        components = ["url", "body", "headers", "cookies"]
        
        for i, pos in enumerate(positions):
            for component in components:
                if component in request:
                    if isinstance(request[component], dict):
                        for k, v in request[component].items():
                            request[component][k] = v.replace(f"§{i}§", str(payloads[i]))
                    else:
                        request[component] = request[component].replace(f"§{i}§", str(payloads[i]))
        return request

    async def _execute_request(self, semaphore, request: Dict, payload: Tuple) -> Tuple:
        """Execute rate-limited HTTP request"""
        async with semaphore:
            try:
                resp = await self.client.request(
                    method=request["method"],
                    url=request["url"],
                    headers=request.get("headers", {}),
                    data=request.get("body"),
                    cookies=request.get("cookies", {})
                )
                return resp, payload
            except Exception as e:
                logger.warning(f"Request failed: {str(e)}")
                return e, payload

    def _analyze_results(self, responses: List) -> Dict:
        """Process responses and detect vulnerabilities"""
        unique_responses = defaultdict(list)
        stats = {
            "total": 0,
            "successful": 0,
            "errors": 0,
            "vulnerabilities": {
                "sqli": 0,
                "xss": 0,
                "idor": 0
            }
        }

        for response in responses:
            if isinstance(response, Exception):
                stats["errors"] += 1
                continue

            resp, payload = response
            stats["total"] += 1
            
            if resp.status_code < 400:
                stats["successful"] += 1
            
            # Normalize and deduplicate
            normalized = self._normalize_response(resp.text)
            response_key = (
                f"{resp.status_code}|||{len(resp.text)}|||"
                f"{hash(normalized)}|||{resp.elapsed.total_seconds()}"
            )
            
            # Detect vulnerabilities
            anomalies = self._detect_vulnerabilities(resp, payload, normalized)
            for vuln in anomalies:
                if anomalies[vuln]:
                    stats["vulnerabilities"][vuln] += 1
            
            unique_responses[response_key].append({
                "payload": payload,
                "anomalies": anomalies,
                "response_time": resp.elapsed.total_seconds()
            })

        # Format results
        results = []
        for key, items in unique_responses.items():
            parts = key.split('|||')
            results.append({
                "count": len(items),
                "payloads": [i["payload"] for i in items],
                "status_code": int(parts[0]),
                "response_length": int(parts[1]),
                "response_hash": parts[2],
                "time_stats": {
                    "avg": sum(i["response_time"] for i in items) / len(items),
                    "max": max(i["response_time"] for i in items)
                },
                "sample_anomalies": items[0]["anomalies"],
                "severity": self._calculate_severity(items[0]["anomalies"])
            })

        return {
            "results": sorted(results, key=lambda x: -x["severity"]),  # Most severe first
            "stats": stats
        }

    def _normalize_response(self, text: str) -> str:
        """Normalize dynamic content for comparison"""
        text = re.sub(r'\b\d{3,}\b', '[NUM]', text)  # Numbers > 3 digits
        text = re.sub(r'0x[0-9a-f]+', '[HEX]', text, flags=re.IGNORECASE)
        text = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]', text)
        return text.lower()

    def _detect_vulnerabilities(self, response: httpx.Response, payload: Tuple, normalized_text: str) -> Dict:
        """Advanced vulnerability detection"""
        payload_str = str(payload).lower()
        
        # SQL Injection
        sql_errors = ["error in your sql", "syntax error", "mysql_", "pg_exec"]
        is_sqli = (
            any(err in normalized_text for err in sql_errors) and
            any(kw in payload_str for kw in ["'", "select ", "union ", "sleep("])
        )
        
        # XSS
        is_xss = (
            any(tag in payload_str for tag in ["<script>", "onerror=", "javascript:"]) and
            (payload_str in normalized_text or 
             any(res in response.headers.get("content-type", "") for res in ["text/html", "application/xhtml"])
        )
        
        # IDOR (Indirect Object Reference)
        is_idor = (
            response.status_code in (200, 403) and
            len(payload[0]) in (16, 32, 64) and  # Likely IDs/hashes
            "access denied" not in normalized_text and
            "login" not in normalized_text
        )
        
        return {
            "sqli": is_sqli,
            "xss": is_xss,
            "idor": is_idor
        }
    def _calculate_severity(self, anomalies: Dict) -> int:
        """Calculate severity score (0-100)"""
        score = 0
        if anomalies["sqli"]:
            score += 80
        if anomalies["xss"]:
            score += 60
        if anomalies["idor"]:
            score += 40
        return min(100, score)

# Singleton instance
intruder_engine = IntruderEngine()
