import time
import pytest
from fastapi.testclient import TestClient
from app import app
from data.database import init_db

init_db()
client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "VulnScan Lite" in data["service"]

def test_trigger_scan_empty_url():
    response = client.post("/api/scan", json={"url": ""})
    assert response.status_code in (400, 422)

def test_trigger_scan_valid_url():
    response = client.post("/api/scan", json={"url": "example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "scan_id" in data
    assert data["status"] == "queued"
    
    # Test checking status
    scan_id = data["scan_id"]
    status_resp = client.get(f"/api/scan/{scan_id}/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["scan_id"] == scan_id
    assert status_data["status"] in ("queued", "running", "completed")

def test_get_scan_history():
    response = client.get("/api/history")
    assert response.status_code == 200
    data = response.json()
    assert "history" in data
    assert isinstance(data["history"], list)

def test_get_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "average_score" in data

def test_rate_limiting():
    # Attempting more than RATE_LIMIT_MAX_REQUESTS within window should trigger 429
    from app import client_scan_requests, RATE_LIMIT_MAX_REQUESTS
    client_scan_requests["testclient"] = [time.time()] * RATE_LIMIT_MAX_REQUESTS
    response = client.post("/api/scan", json={"url": "test.com"})
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]
    assert "Retry-After" in response.headers
    # Clean up
    client_scan_requests["testclient"] = []
