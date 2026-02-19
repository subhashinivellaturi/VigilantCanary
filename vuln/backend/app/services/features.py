from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List

SUSPICIOUS_TOKENS = [
    "<script",
    "onerror",
    "onclick",
    "drop table",
    "union select",
    "../",
    "<?php",
    "{{",
]

SQL_KEYWORDS = ["select", "insert", "update", "delete", "sleep", "union", "drop", "exec"]
SENSITIVE_FILES = [".env", "config.php", "web.config", "id_rsa", "passwd"]
JS_EVENTS = ["onload", "onfocus", "onmouseover", "onmouseenter"]


@dataclass
class FeatureBundle:
    values: List[float]
    labels: List[str]


_token_regex = re.compile(r"[A-Za-z0-9_:\-/\.]+")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log(probability, 2)
    return entropy


def _count_matches(tokens: List[str], text: str) -> int:
    lowered = text.lower()
    return sum(1 for token in tokens if token in lowered)


def _tokenize(text: str) -> List[str]:
    return _token_regex.findall(text.lower())


def extract_features(url: str, payload: str) -> FeatureBundle:
    combined = f"{url} {payload}".strip()
    tokens = _tokenize(combined)

    halstead = _halstead_metrics(combined)
    cyclomatic = _cyclomatic_density(combined)

    feature_map = {
        "url_length": len(url),
        "payload_length": len(payload),
        "num_params": url.count("=") + payload.count("="),
        "suspicious_token_count": _count_matches(SUSPICIOUS_TOKENS, combined),
        "script_tag_count": payload.lower().count("<script"),
        "sql_keyword_count": _count_matches(SQL_KEYWORDS, combined),
        "sensitive_file_hits": _count_matches(SENSITIVE_FILES, combined),
        "js_event_count": _count_matches(JS_EVENTS, combined),
        "entropy": shannon_entropy(payload or url),
        "uppercase_ratio": _uppercase_ratio(combined),
        "numeric_density": _numeric_density(tokens),
        **halstead,
        "cyclomatic_density": cyclomatic,
    }

    return FeatureBundle(values=list(feature_map.values()), labels=list(feature_map.keys()))


def _uppercase_ratio(text: str) -> float:
    if not text:
        return 0.0
    uppers = sum(1 for char in text if char.isupper())
    return uppers / len(text)


def _numeric_density(tokens: List[str]) -> float:
    if not tokens:
        return 0.0
    numeric_tokens = sum(1 for token in tokens if token.isdigit())
    return numeric_tokens / len(tokens)


def _halstead_metrics(text: str) -> Dict[str, float]:
    """Simplified Halstead metrics for text."""
    tokens = _tokenize(text)
    operators = ['=', '+', '-', '*', '/', '%', '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!', '&', '|', '^', '~', '<<', '>>', '>>>']
    operands = []
    operator_count = 0
    for token in tokens:
        if token in operators:
            operator_count += 1
        else:
            operands.append(token)
    
    n1 = len(set(operators))  # unique operators
    n2 = len(set(operands))   # unique operands
    N1 = operator_count       # total operators
    N2 = len(operands)        # total operands
    
    if n1 + n2 == 0:
        return {"halstead_length": 0, "halstead_vocabulary": 0, "halstead_volume": 0, "halstead_difficulty": 0, "halstead_effort": 0}
    
    length = N1 + N2
    vocabulary = n1 + n2
    volume = length * math.log(vocabulary, 2) if vocabulary > 1 else 0
    difficulty = (n1 * N2) / (2 * n2) if n2 > 0 else 0
    effort = difficulty * volume
    
    return {
        "halstead_length": length,
        "halstead_vocabulary": vocabulary,
        "halstead_volume": volume,
        "halstead_difficulty": difficulty,
        "halstead_effort": effort,
    }


def _cyclomatic_density(text: str) -> float:
    """Simplified cyclomatic complexity density."""
    tokens = _tokenize(text)
    control_keywords = ['if', 'else', 'for', 'while', 'do', 'switch', 'case', 'try', 'catch', 'finally']
    control_count = sum(1 for token in tokens if token in control_keywords)
    total_statements = len([t for t in tokens if t.endswith(';') or t in ['{', '}']])
    return control_count / max(total_statements, 1)
