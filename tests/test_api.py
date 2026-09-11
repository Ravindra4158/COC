from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analysis_endpoints():
    assert client.get("/analysis").status_code == 200
    network = client.get("/network")
    vulnerabilities = client.get("/vulnerabilities")
    recommendations = client.get("/recommendations")
    assert network.status_code == 200
    assert len(network.json()["nodes"]) == 40
    assert vulnerabilities.status_code == 200
    assert len(vulnerabilities.json()["items"]) == 80
    assert recommendations.status_code == 200
    assert len(recommendations.json()["items"]) == 10


def test_refresh():
    response = client.post("/analysis/run")
    assert response.status_code == 200
    assert response.json()["status"] == "complete"
