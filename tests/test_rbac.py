from auth import generate_token


def _auth(role, tenant=1):
    return {"Authorization": f"Bearer {generate_token(1, role=role, tenant_id=tenant)}"}


def test_viewer_cannot_create_incident(client):
    resp = client.post("/incidents", json={"description": "x"}, headers=_auth("viewer"))
    assert resp.status_code == 403


def test_analyst_cannot_create_tenant(client):
    resp = client.post("/admin/tenants", json={"name": "acme"}, headers=_auth("analyst"))
    assert resp.status_code == 403


def test_unauthenticated_incident_list(client):
    assert client.get("/incidents").status_code == 401
