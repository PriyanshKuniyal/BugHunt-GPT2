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
    """Generates payloads efficiently (lazy evaluation for large sets)."""
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
    """Lazy brute-force generator to avoid memory overload."""
    from itertools import permutations
    for length in range(min_len, max_len + 1):
        for p in product(charset, repeat=length):
            yield ''.join(p)

class IntruderEngine:
    """Core Intruder logic with async HTTP and response deduplication."""
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0, limits=httpx.Limits(max_connections=100))

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
        
        # Execute requests and deduplicate responses
        unique_responses = defaultdict(list)
        tasks = []
        for combo in payload_combinations[:max_requests]:
            modified_request = self._replace_payloads(base_request, payload_positions, combo)
            tasks.append(self._send_request(modified_request, combo))
        
        # Process responses as they complete
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for resp, payload in responses:
            if isinstance(resp, Exception):
                logger.error(f"Request failed: {resp}")
                continue
            response_key = self._response_key(resp)
            unique_responses[response_key].append(payload)

        # Format results (group duplicates)
        results = []
        for key, payloads in unique_responses.items():
            resp = key.split('|||')
            results.append({
                "payloads": payloads,
                "count": len(payloads),
                "status_code": int(resp[0]),
                "response_length": int(resp[1]),
                "response_body": resp[2] if len(resp) > 2 else None,
            })

        return {"results": results}

    def _generate_combinations(self, attack_type: str, payload_sets: List[Dict]) -> List[Tuple]:
        """Generate payload combinations based on attack type."""
        payloads = [PayloadGenerator.generate(config) for config in payload_sets]
        if attack_type == AttackType.SNIPER:
            return [(p,) for p in payloads[0]]
        elif attack_type == AttackType.CLUSTER_BOMB:
            return list(product(*payloads))
        raise ValueError(f"Unsupported attack type: {attack_type}")

    def _replace_payloads(self, request: Dict, positions: List[str], payloads: Tuple) -> Dict:
        """Replace §0§, §1§, etc., with actual payloads."""
        modified = request.copy()
        for i, pos in enumerate(positions):
            modified["url"] = modified["url"].replace(f"§{i}§", payloads[i])
            if "body" in modified:
                modified["body"] = modified["body"].replace(f"§{i}§", payloads[i])
        return modified

    async def _send_request(self, request: Dict, payload: Tuple) -> Tuple[Union[httpx.Response, Exception], Tuple]:
        """Send an async HTTP request and return (response, payload)."""
        try:
            resp = await self.client.request(
                method=request["method"],
                url=request["url"],
                headers=request.get("headers", {}),
                data=request.get("body"),
            )
            return resp, payload
        except Exception as e:
            return e, payload

    def _response_key(self, response: httpx.Response) -> str:
        """Create a unique key for deduplication (status + length + body hash)."""
        body_hash = hash(response.text)  # Faster than storing full body
        return f"{response.status_code}|||{len(response.text)}|||{body_hash}"

# Singleton for reuse
intruder_engine = IntruderEngine()
