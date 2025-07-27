import jwt
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Add these imports at the top with others
import base64
import binascii

class SequencerEngine:
    # ... [keep all existing methods] ...
    
    def _perform_analysis(self, tokens: List[str]) -> Dict:
        """Enhanced analysis with JWT detection"""
        analysis = {
            "basic_stats": self._basic_statistics(tokens),
            "entropy": self._entropy_analysis(tokens),
            "statistical_tests": self._statistical_tests(tokens),
            "pattern_detection": self._pattern_detection(tokens),
            "jwt_analysis": self._analyze_jwts(tokens)  # New JWT analysis
        }
        
        analysis["quality_score"] = self._calculate_quality_score(
            analysis["entropy"],
            analysis["statistical_tests"],
            analysis["pattern_detection"],
            analysis["jwt_analysis"]  # Include in scoring
        )
        return analysis

    def _analyze_jwts(self, tokens: List[str]) -> Dict:
        """Comprehensive JWT validation and analysis"""
        jwt_results = {
            "jwts_found": 0,
            "vulnerable": [],
            "claims_analysis": defaultdict(list),
            "crypto_weaknesses": []
        }

        for token in tokens:
            if not self._is_jwt(token):
                continue

            jwt_results["jwts_found"] += 1
            analysis = self._inspect_jwt(token)
            
            if analysis["is_vulnerable"]:
                jwt_results["vulnerable"].append({
                    "token_prefix": token[:30] + "...",
                    "issues": analysis["issues"]
                })
            
            # Track common claims
            for claim, value in analysis["claims"].items():
                jwt_results["claims_analysis"][claim].append(value)

            # Track crypto issues
            if analysis["crypto_issue"]:
                jwt_results["crypto_weaknesses"].append(analysis["crypto_issue"])

        # Add statistical analysis of claims
        if jwt_results["jwts_found"] > 0:
            jwt_results["claims_stats"] = self._analyze_jwt_claims(jwt_results["claims_analysis"])
            
        return jwt_results

    def _is_jwt(self, token: str) -> bool:
        """Check if token is a JWT"""
        parts = token.split('.')
        return len(parts) == 3 and all(len(part) > 0 for part in parts)

    def _inspect_jwt(self, token: str) -> Dict:
        """Deep inspection of a single JWT"""
        result = {
            "is_vulnerable": False,
            "issues": [],
            "claims": {},
            "crypto_issue": None
        }

        try:
            # Attempt to decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            result["claims"] = decoded
            
            # Check for common vulnerabilities
            if decoded.get("alg") == "none":
                result["is_vulnerable"] = True
                result["issues"].append("none_algorithm")
                result["crypto_issue"] = "none_algorithm"

            if decoded.get("alg") == "HS256":
                if len(decoded.get("jti", "")) < 16:
                    result["is_vulnerable"] = True
                    result["issues"].append("weak_hs256_key")

            # Check expiration
            if decoded.get("exp"):
                exp_time = datetime.fromtimestamp(decoded["exp"])
                if exp_time < datetime.now():
                    result["issues"].append("expired")

            # Check header injections
            header = jwt.get_unverified_header(token)
            if header.get("kid") and ("/" in header["kid"] or "\\" in header["kid"]):
                result["is_vulnerable"] = True
                result["issues"].append("header_injection_risk")

        except (jwt.DecodeError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
            result["issues"].append("malformed_jwt")
            result["is_vulnerable"] = True

        return result

    def _analyze_jwt_claims(self, claims: Dict) -> Dict:
        """Statistical analysis of JWT claims"""
        stats = {}
        
        for claim, values in claims.items():
            # Numeric claim analysis
            if all(isinstance(v, (int, float)) for v in values):
                vals = [float(v) for v in values]
                stats[claim] = {
                    "type": "numeric",
                    "min": min(vals),
                    "max": max(vals),
                    "mean": np.mean(vals),
                    "variance": np.var(vals)
                }
            # Timestamp claim analysis
            elif claim in ["exp", "iat", "nbf"]:
                timestamps = [datetime.fromtimestamp(float(v)) for v in values]
                stats[claim] = {
                    "type": "timestamp",
                    "min": min(timestamps).isoformat(),
                    "max": max(timestamps).isoformat(),
                    "avg_expiry": str((max(timestamps) - min(timestamps)) / len(timestamps))
                }
            # Categorical analysis
            else:
                freq = defaultdict(int)
                for v in values:
                    freq[str(v)] += 1
                stats[claim] = {
                    "type": "categorical",
                    "unique_values": len(freq),
                    "most_common": sorted(freq.items(), key=lambda x: -x[1])[:3]
                }

        return stats

    def _calculate_quality_score(self, entropy: Dict, tests: Dict, patterns: Dict, jwt: Dict) -> float:
        """Enhanced scoring with JWT factors"""
        score = 0
        
        # Base score from original factors (60%)
        score += min(100, entropy["shannon"] * 10) * 0.3
        test_score = sum(25 for test in tests.values() if test.get("passed", False))
        score += test_score * 0.3
        
        # JWT factors (40%)
        if jwt["jwts_found"] > 0:
            jwt_penalty = 0
            if jwt["vulnerable"]:
                jwt_penalty += min(30, len(jwt["vulnerable"]) * 5)
            if jwt["crypto_weaknesses"]:
                jwt_penalty += min(20, len(jwt["crypto_weaknesses"]) * 4)
            
            # Bonus for secure JWTs
            if not jwt["vulnerable"] and not jwt["crypto_weaknesses"]:
                score += 20
            
            score -= jwt_penalty
        
        # Pattern penalties (20%)
        pattern_penalty = sum(
            10 for pattern in patterns.values() 
            if pattern["count"] > 0
        )
        score -= min(20, pattern_penalty)
        
        return max(0, min(100, score))

# Add to requirements.txt:
# pyjwt>=2.3.0
# cryptography>=3.4
