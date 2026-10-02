from auth import generate_token, verify_token


def test_token_round_trip_includes_role_and_tenant():
    token = generate_token(7, role="responder", tenant_id=3)
    identity = verify_token(token)
    assert identity["id"] == 7
    assert identity["role"] == "responder"
    assert identity["tenant_id"] == 3


def test_invalid_token_rejected():
    assert verify_token("not-a-token") is None


def test_impersonation_claim_propagates():
    token = generate_token(9, role="analyst", tenant_id=1, impersonator=2)
    assert verify_token(token)["impersonator"] == 2
