from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from typing import List

from ..models.schemas import VulnerabilityRequest, VulnerabilityResponse
from ..services.inference import InferenceService
from ..services.recommendations import RecommendationService
from ..services.self_evolving_detector import SelfEvolvingDetector
from ..services.sequential_workflow import SequentialWorkflowEngine
from ..services.subdomain_enumerator import SubdomainEnumerator
from ..services.scan_history import ScanHistoryDB

router = APIRouter()

# Health check endpoint
@router.get("/health")
def health_check():
    try:
        return {"status": "healthy", "message": "Service is running"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Service unhealthy: {str(e)}")

# Vulnerability analysis endpoint
@router.post("/analyze", response_model=VulnerabilityResponse)
def analyze_payload(request: VulnerabilityRequest):
    try:
        # For now, return a mock response
        return VulnerabilityResponse(
            vulnerabilities=[],
            severity="low",
            confidence=0.5,
            recommendations=[],
            metadata={"analyzed_at": "now", "url": request.url}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Subdomain enumeration endpoint
@router.post("/enumerate-subdomains")
def enumerate_subdomains(domain: str, use_brute_force: bool = False):
    try:
        # For now, return mock results
        mock_subdomains = [f"www.{domain}", f"api.{domain}", f"test.{domain}"]
        return {
            "scan_id": "mock_scan_123",
            "domain": domain,
            "subdomains_found": len(mock_subdomains),
            "subdomains": mock_subdomains,
            "brute_force_used": use_brute_force
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Subdomain enumeration failed: {str(e)}")

# Get recent scans
@router.get("/recent-scans")
def get_recent_scans(limit: int = 10):
    try:
        # Mock data for now
        return {"scans": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scans: {str(e)}")

# Get recent subdomain scans
@router.get("/recent-subdomain-scans")
def get_recent_subdomain_scans(limit: int = 10):
    try:
        # Mock data for now
        return {"scans": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve subdomain scans: {str(e)}")

# Get recent vulnerabilities
@router.get("/recent-vulnerabilities")
def get_recent_vulnerabilities(limit: int = 10):
    try:
        # Mock data for now
        return {"vulnerabilities": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve vulnerabilities: {str(e)}")

# Dashboard summary data
@router.get("/dashboard-summary")
def get_dashboard_summary():
    try:
        # Mock dashboard data
        return {
            "total_scans": 152,
            "critical_vulnerabilities": 12,
            "high_vulnerabilities": 28,
            "medium_vulnerabilities": 45,
            "low_vulnerabilities": 67,
            "active_assets": 89
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard summary: {str(e)}")

# Test endpoint
@router.get("/test")
def test_endpoint():
    return {"message": "API is working", "status": "ok"}
