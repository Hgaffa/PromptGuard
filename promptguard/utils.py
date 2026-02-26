"""Utility functions for PromptGuard."""

from typing import List, Dict, Any, Optional
import numpy as np
from .schemas import RiskScore


def summarize_results(results: List[RiskScore]) -> Dict[str, Any]:
    """
    Summarize a list of analysis results.

    Args:
        results: List of RiskScore objects

    Returns:
        Dictionary with summary statistics
    """
    # Filter out None results
    valid_results = [r for r in results if r is not None]

    if not valid_results:
        return {
            "total": 0,
            "valid": 0,
            "malicious_count": 0,
            "benign_count": 0,
            "malicious_percentage": 0.0,
            "avg_probability": 0.0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0
        }

    malicious = [r for r in valid_results if r.is_malicious]
    benign = [r for r in valid_results if not r.is_malicious]

    probabilities = [r.probability for r in valid_results]

    risk_counts = {
        "high": sum(1 for r in valid_results if r.risk_level.value == "high"),
        "medium": sum(1 for r in valid_results if r.risk_level.value == "medium"),
        "low": sum(1 for r in valid_results if r.risk_level.value == "low")
    }

    return {
        "total": len(results),
        "valid": len(valid_results),
        "invalid": len(results) - len(valid_results),
        "malicious_count": len(malicious),
        "benign_count": len(benign),
        "malicious_percentage": (len(malicious) / len(valid_results) * 100),
        "avg_probability": np.mean(probabilities),
        "min_probability": np.min(probabilities),
        "max_probability": np.max(probabilities),
        "std_probability": np.std(probabilities),
        "high_risk_count": risk_counts["high"],
        "medium_risk_count": risk_counts["medium"],
        "low_risk_count": risk_counts["low"]
    }


def filter_by_risk_level(
    results: List[RiskScore],
    risk_level: str
) -> List[RiskScore]:
    """
    Filter results by risk level.

    Args:
        results: List of RiskScore objects
        risk_level: Risk level to filter by ('low', 'medium', 'high')

    Returns:
        Filtered list of results
    """
    return [
        r for r in results
        if r is not None and r.risk_level.value == risk_level.lower()
    ]


def get_most_dangerous(
    results: List[RiskScore],
    top_n: int = 10
) -> List[RiskScore]:
    """
    Get the most dangerous prompts from results.

    Args:
        results: List of RiskScore objects
        top_n: Number of top results to return

    Returns:
        List of top N most dangerous prompts
    """
    valid_results = [r for r in results if r is not None]
    sorted_results = sorted(
        valid_results,
        key=lambda x: x.probability,
        reverse=True
    )
    return sorted_results[:top_n]


def export_to_csv(
    results: List[RiskScore],
    prompts: List[str],
    filename: str
):
    """
    Export results to CSV file.

    Args:
        results: List of RiskScore objects
        prompts: Original prompts
        filename: Output CSV filename
    """
    import csv

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'prompt',
            'is_malicious',
            'probability',
            'risk_level',
            'confidence',
            'explanation'
        ])

        for prompt, result in zip(prompts, results):
            if result is not None:
                writer.writerow([
                    prompt,
                    result.is_malicious,
                    f"{result.probability:.4f}",
                    result.risk_level.value,
                    f"{result.confidence:.4f}",
                    result.explanation
                ])


def results_to_dataframe(
    results: List[RiskScore],
    prompts: Optional[List[str]] = None
):
    """
    Convert results to pandas DataFrame.
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError(
            "pandas is required for this function. "
            "Install it with: pip install pandas"
        )

    data = []
    for i, result in enumerate(results):
        if result is not None:
            row = {
                'is_malicious': result.is_malicious,
                'probability': result.probability,
                'risk_level': result.risk_level.value,
                'confidence': result.confidence
            }

            if prompts is not None and i < len(prompts):
                row['prompt'] = prompts[i]

            data.append(row)

    return pd.DataFrame(data)
