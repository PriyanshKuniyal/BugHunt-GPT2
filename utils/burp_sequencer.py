import asyncio
import random
import time
from typing import Dict, List, Optional
import httpx
from dataclasses import dataclass
import logging
import numpy as np
from scipy import stats
import entropy

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
            follow_redirects=False
        )
        self.config = SequencerConfig()

    async def analyze(self, base_request: Dict, token_locations: List[Dict]) -> Dict:
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
                    sample = {}
                    for loc in token_locations:
                        token = self._extract_token(resp, loc)
                        if token:
                            sample[f"{loc['type']}:{loc['name']}"] = token
                    return sample
                except Exception as e:
                    logger.warning(f"Sample collection failed: {str(e)}")
                    return None

        tasks = [fetch_sample() for _ in range(self.config.sample_size)]
        for future in asyncio.as_completed(tasks):
            sample = await future
            if sample:
                samples.append(sample)
                if len(samples) % 100 == 0:
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

    def _analyze_samples(self, samples: List[Dict], token_locations: List[Dict]) -> Dict:
        """Analyze collected token samples"""
        results = {}
        for loc in token_locations:
            loc_key = f"{loc['type']}:{loc['name']}"
            tokens = [s[loc_key] for s in samples if loc_key in s]
            
            if len(tokens) < self.config.analysis_threshold:
                logger.warning(f"Insufficient samples for {loc_key}")
                continue

            results[loc_key] = {
                "entropy": self._calculate_entropy(tokens),
                "randomness_tests": self._run_randomness_tests(tokens),
                "basic_stats": self._calculate_stats(tokens)
            }
        return {
            "results": results,
            "metadata": {
                "total_samples": len(samples),
                "analysis_threshold": self.config.analysis_threshold
            }
        }

    def _calculate_entropy(self, tokens: List[str]) -> Dict:
        """Calculate entropy metrics"""
        byte_samples = [t.encode() for t in tokens]
        return {
            "shannon": entropy.shannon_entropy(b''.join(byte_samples)),
            "min": min(entropy.shannon_entropy(t) for t in byte_samples),
            "max": max(entropy.shannon_entropy(t) for t in byte_samples),
            "mean": np.mean([entropy.shannon_entropy(t) for t in byte_samples])
        }

    def _run_randomness_tests(self, tokens: List[str]) -> Dict:
        """Run statistical randomness tests"""
        char_samples = [ord(c) for t in tokens for c in t]
        return {
            "chi_square": self._chi_square_test(char_samples),
            "runs_test": self._runs_test(char_samples)
        }

    def _calculate_stats(self, tokens: List[str]) -> Dict:
        """Calculate basic statistics"""
        lengths = [len(t) for t in tokens]
        return {
            "count": len(tokens),
            "length": {
                "min": min(lengths),
                "max": max(lengths),
                "mean": np.mean(lengths),
                "std": np.std(lengths)
            },
            "unique_tokens": len(set(tokens))
        }

    def _chi_square_test(self, data: List[int]) -> Dict:
        """Chi-square goodness-of-fit test"""
        observed = np.bincount(data, minlength=256)
        expected = np.full(256, len(data)/256)
        chi2 = np.sum((observed - expected)**2 / expected)
        return {
            "statistic": float(chi2),
            "p_value": float(1 - stats.chi2.cdf(chi2, 255)),
            "passed": chi2 < 300
        }

    def _runs_test(self, data: List[int]) -> Dict:
        """Wald-Wolfowitz runs test"""
        median = np.median(data)
        runs = 1
        prev = data[0] > median

        for val in data[1:]:
            current = val > median
            if current != prev:
                runs += 1
            prev = current

        n1 = sum(1 for val in data if val > median)
        n2 = len(data) - n1
        expected_runs = (2 * n1 * n2) / (n1 + n2) + 1
        std_dev = np.sqrt((2 * n1 * n2 * (2 * n1 * n2 - n1 - n2)) / 
                         ((n1 + n2)**2 * (n1 + n2 - 1)))

        z_score = (runs - expected_runs) / std_dev
        return {
            "runs": runs,
            "z_score": float(z_score),
            "p_value": float(2 * (1 - stats.norm.cdf(abs(z_score)))),
            "passed": abs(z_score) < 1.96
        }

# Create the singleton instance
sequencer_engine = SequencerEngine()
