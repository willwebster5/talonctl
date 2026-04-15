#!/usr/bin/env python3
"""
Template Matcher - Fuzzy matching logic for CrowdStrike template discovery
"""

import re
from difflib import SequenceMatcher
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class TemplateMatcher:
    """Handles fuzzy matching between CrowdStrike templates and local rules"""

    # Common prefixes/suffixes to strip for matching
    STRIP_PREFIXES = [
        "needs tuning",
        "needs_tuning",
        "draft",
        "test",
        "temp",
        "wip",
        "experimental",
        "poc",
        "updated",
        "(updated)",
        "new",
    ]

    STRIP_SUFFIXES = [
        "experimental",
        "test",
        "draft",
        "temp",
        "copy",
        "backup",
        "v1",
        "v2",
        "v3",
        "old",
        "new",
        "enhanced",
        "advanced",
    ]

    # Vendor patterns
    VENDOR_PATTERNS = {
        "aws": r"^aws\s*[-_]\s*",
        "microsoft": r"^microsoft\s*[-_]\s*",
        "google": r"^google\s*[-_]\s*",
        "crowdstrike": r"^crowdstrike\s*[-_]\s*",
        "generic": r"^generic\s*[-_]\s*",
        "sase": r"^sase\s*[-_]\s*",
    }

    def __init__(self, match_threshold: float = 80.0):
        """
        Initialize the matcher with a threshold

        Args:
            match_threshold: Minimum score (0-100) to consider a match
        """
        self.match_threshold = match_threshold
        self._normalized_cache = {}

    def normalize_name(self, name: str) -> str:
        """
        Normalize a rule name for comparison

        Args:
            name: The rule name to normalize

        Returns:
            Normalized name
        """
        if name in self._normalized_cache:
            return self._normalized_cache[name]

        normalized = name.lower()

        # Remove vendor prefixes
        for vendor, pattern in self.VENDOR_PATTERNS.items():
            normalized = re.sub(pattern, "", normalized, flags=re.I)

        # Remove common prefixes
        for prefix in self.STRIP_PREFIXES:
            pattern = f"^{re.escape(prefix)}\\s*[-_]?\\s*"
            normalized = re.sub(pattern, "", normalized, flags=re.I)
            # Also check with parentheses
            pattern = f"^\\({re.escape(prefix)}\\)\\s*[-_]?\\s*"
            normalized = re.sub(pattern, "", normalized, flags=re.I)

        # Remove common suffixes
        for suffix in self.STRIP_SUFFIXES:
            pattern = f"\\s*[-_]?\\s*{re.escape(suffix)}$"
            normalized = re.sub(pattern, "", normalized, flags=re.I)
            # Also check with parentheses
            pattern = f"\\s*[-_]?\\s*\\({re.escape(suffix)}\\)$"
            normalized = re.sub(pattern, "", normalized, flags=re.I)

        # Standardize separators
        normalized = re.sub(r"[-_\s]+", " ", normalized)

        # Remove extra whitespace
        normalized = " ".join(normalized.split())

        self._normalized_cache[name] = normalized
        return normalized

    def token_similarity(self, name1: str, name2: str) -> float:
        """
        Calculate token-based similarity between two names

        Args:
            name1: First name
            name2: Second name

        Returns:
            Similarity score (0-100)
        """
        # Tokenize
        tokens1 = set(self.normalize_name(name1).split())
        tokens2 = set(self.normalize_name(name2).split())

        if not tokens1 or not tokens2:
            return 0.0

        # Calculate Jaccard similarity
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2

        if not union:
            return 0.0

        jaccard = len(intersection) / len(union)

        # Boost score if all tokens from shorter set are in longer set
        if tokens1.issubset(tokens2) or tokens2.issubset(tokens1):
            jaccard = min(jaccard + 0.2, 1.0)

        return jaccard * 100

    def sequence_similarity(self, name1: str, name2: str) -> float:
        """
        Calculate sequence-based similarity (Levenshtein-like)

        Args:
            name1: First name
            name2: Second name

        Returns:
            Similarity score (0-100)
        """
        norm1 = self.normalize_name(name1)
        norm2 = self.normalize_name(name2)

        # Use SequenceMatcher for similarity ratio
        ratio = SequenceMatcher(None, norm1, norm2).ratio()
        return ratio * 100

    def key_phrase_match(self, name1: str, name2: str) -> float:
        """
        Check for matching key security phrases

        Args:
            name1: First name
            name2: Second name

        Returns:
            Similarity score (0-100)
        """
        # Key phrases that indicate similar rules
        key_phrases = [
            "brute force",
            "privilege escalation",
            "lateral movement",
            "data exfiltration",
            "persistence",
            "defense evasion",
            "credential access",
            "discovery",
            "execution",
            "collection",
            "command and control",
            "c2",
            "initial access",
            "impact",
            "mfa",
            "multi factor",
            "two factor",
            "2fa",
            "root account",
            "admin account",
            "service account",
            "api key",
            "access key",
            "secret key",
            "public access",
            "public bucket",
            "public share",
            "suspicious",
            "anomalous",
            "unusual",
            "unauthorized",
            "enumeration",
            "reconnaissance",
            "scanning",
            "policy change",
            "configuration change",
            "permission change",
            "console login",
            "cli access",
            "api access",
        ]

        norm1 = self.normalize_name(name1)
        norm2 = self.normalize_name(name2)

        matched_phrases = 0
        total_phrases = 0

        for phrase in key_phrases:
            if phrase in norm1 or phrase in norm2:
                total_phrases += 1
                if phrase in norm1 and phrase in norm2:
                    matched_phrases += 1

        if total_phrases == 0:
            return 50.0  # Neutral score if no key phrases

        return (matched_phrases / total_phrases) * 100

    def calculate_match_score(self, template_name: str, local_name: str) -> float:
        """
        Calculate overall match score between template and local rule

        Args:
            template_name: Template rule name
            local_name: Local rule name

        Returns:
            Match score (0-100)
        """
        # Check for exact match after normalization
        if self.normalize_name(template_name) == self.normalize_name(local_name):
            return 100.0

        # Calculate component scores
        token_score = self.token_similarity(template_name, local_name)
        sequence_score = self.sequence_similarity(template_name, local_name)
        phrase_score = self.key_phrase_match(template_name, local_name)

        # Weighted average
        # Token similarity is most important (40%)
        # Sequence similarity is important (35%)
        # Key phrase matching is supporting (25%)
        weighted_score = token_score * 0.40 + sequence_score * 0.35 + phrase_score * 0.25

        return weighted_score

    def find_best_match(self, template_name: str, local_rules: List[Dict]) -> Tuple[Optional[Dict], float]:
        """
        Find the best matching local rule for a template

        Args:
            template_name: Template rule name
            local_rules: List of local rule dictionaries

        Returns:
            Tuple of (best_matching_rule, score)
        """
        best_match = None
        best_score = 0.0

        for rule in local_rules:
            rule_name = rule.get("name", "")
            score = self.calculate_match_score(template_name, rule_name)

            if score > best_score:
                best_score = score
                best_match = rule

        return best_match, best_score

    def is_match(self, score: float) -> bool:
        """
        Check if a score meets the match threshold

        Args:
            score: Match score

        Returns:
            True if score meets threshold
        """
        return score >= self.match_threshold

    def classify_match(self, score: float) -> str:
        """
        Classify the match quality based on score

        Args:
            score: Match score

        Returns:
            Classification string
        """
        if score >= 95:
            return "exact"
        elif score >= 80:
            return "matched"
        elif score >= 70:
            return "possible_duplicate"
        elif score >= 50:
            return "similar"
        else:
            return "unrelated"
