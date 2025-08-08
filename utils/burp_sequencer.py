import asyncio
import httpx
import logging
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Optional
from scipy import stats

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SequencerConfig:
    sample_size: int = 500
    concurrency: int = 50
    analysis_threshold: int = 100

class SequencerEngine:
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            limits=httpx.Limits(max_connections=100),
            http2=True,
            follow_redirects=True  # Robust: follow redirects for real-world and httpbin
        )
        self.config = SequencerConfig()

    def _shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a byte string"""
        if not data:
            return 0.0
        from collections import Counter
        import math

        counter = Counter(data)
        total = len(data)
        entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
        return entropy

    async def analyze(
        self,
        base_request: Dict,
        token_locations: List[Dict]
    ) -> Dict:
        """Main analysis method"""
        try:
            samples = await self._collect_samples(base_request, token_locations)
            return self._analyze_samples(samples, token_locations)
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {"error": str(e)}

    async def _collect_samples(self, base_request: Dict, token_locations: List[Dict]) -> List[Dict]:
        """Collect token samples from target"""
        samples = []
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def fetch_sample():
            async with semaphore:
                try:
                    resp = await self.client.request(
                        method=base_request["method"],
                        url=base_request["url"],
                        headers=base_request.get("headers", {}),
                        cookies=base_request.get("cookies", {}),
                        data=base_request.get("body")
                    )

                    # Robust: Combine cookies from final response and from Set-Cookie headers in the redirect chain
                    tokens_found = {}
                    # 1. Check cookies in the final response object
                    for loc in token_locations:
                        token = self._extract_token(resp, loc)
                        if token:
                            tokens_found[f"{loc['type']}:{loc['name']}"] = token

                    # 2. Check Set-Cookie headers in the history (redirect chain)
                    if hasattr(resp, "history"):
                        for prev_response in resp.history:
                            for loc in token_locations:
                                token = self._extract_token_from_headers(prev_response, loc)
                                if token:
                                    tokens_found[f"{loc['type']}:{loc['name']}"] = token

                    logger.debug(f"Sample tokens found: {tokens_found}")
                    return tokens_found if tokens_found else None

                except Exception as e:
                    logger.warning(f"Sample collection failed: {str(e)}")
                    return None

        tasks = [fetch_sample() for _ in range(self.config.sample_size)]
        for future in asyncio.as_completed(tasks):
            sample = await future
            if sample:
                samples.append(sample)
                if len(samples) % 10 == 0:
                    logger.info(f"Collected {len(samples)} samples")
        return samples

    def _extract_token(self, response: httpx.Response, location: Dict) -> Optional[str]:
        """Extract token from response based on location"""
        try:
            if location["type"] == "cookie":
                return response.cookies.get(location["name"])
            elif location["type"] == "header":
                return response.headers.get(location["name"])
            return None
        except Exception:
            return None

    def _extract_token_from_headers(self, response: httpx.Response, location: Dict) -> Optional[str]:
        """Extract token from Set-Cookie header in a response"""
        if location["type"] != "cookie":
            return None
        # httpx >= 0.23: get_list for multiple Set-Cookie headers
        set_cookie_headers = response.headers.get_list("set-cookie")
        for header in set_cookie_headers:
            cookie_pair = header.split(";", 1)[0]
            if "=" in cookie_pair:
                name, value = cookie_pair.split("=", 1)
                if name.strip() == location["name"]:
                    return value
        return None

    def _analyze_samples(self, samples: List[Dict], token_locations: List[Dict]) -> Dict:
        """Analyze collected token samples"""
        results = {}
        for loc in token_locations:
            loc_key = f"{loc['type']}:{loc['name']}"
            tokens = [s[loc_key] for s in samples if loc_key in s and s[loc_key] is not None]

            if len(tokens) < self.config.analysis_threshold:
                logger.warning(f"Insufficient samples for {loc_key}")
                continue

            entropy = self._shannon_entropy("".join(tokens).encode())
            unique_tokens = len(set(tokens))
            duplicates = len(tokens) - unique_tokens
            token_lengths = [len(t) for t in tokens]
            median_length = np.median(token_lengths)
            stdev_length = np.std(token_lengths)
            chi2, pval = self._chi_squared_uniformity(tokens)

            results[loc_key] = {
                "total_samples": len(tokens),
                "unique_tokens": unique_tokens,
                "duplicates": duplicates,
                "entropy": entropy,
                "median_length": median_length,
                "stdev_length": stdev_length,
                "chi2_stat": chi2,
                "p_value": pval,
                "token_example": tokens[:5]
            }

        return {
            "metadata": {
                "analysis_threshold": self.config.analysis_threshold,
                "total_samples": len(samples)
            },
            "results": results
        }

    def _chi_squared_uniformity(self, tokens: List[str]):
        """Perform chi-squared test for uniformity, robust to zero counts."""
        if not tokens:
            return None, None
        chars = "".join(tokens)
        if not chars:
            return None, None
        values = [ord(c) for c in chars]
        freq = np.bincount(values)
        # Only keep nonzero bins for observed and expected
        observed = freq[freq > 0]
        n = observed.sum()
        expected = np.full_like(observed, n / len(observed))
        chi2, pval = stats.chisquare(observed, expected)
        return float(chi2), float(pval)

sequencer_engine = SequencerEngine()
