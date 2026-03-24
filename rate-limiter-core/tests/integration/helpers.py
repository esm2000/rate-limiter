def create_service_via_api(client, name, password):
    resp = client.post("/service", json={"service_name": name, "admin_password": password})
    data = resp.get_json()
    return data["service_id"], data["api_key"], data["admin_user_id"]


def create_user_via_api(client, api_key, service_id, password, is_admin=False):
    resp = client.post("/user", json={
        "service_id": service_id, "password": password, "is_admin": is_admin
    }, headers={"Authorization": f"Bearer {api_key}"})
    return resp.get_json()["user_id"]


def create_rule_via_api(client, api_key, domain, category, identifier, rate_limit, window_size, algorithm):
    return client.post("/rule", json={
        "domain": domain, "category": category, "identifier": identifier,
        "rate_limit": rate_limit, "window_size": window_size, "algorithm": algorithm
    }, headers={"Authorization": f"Bearer {api_key}"})


def setup_service_and_rule(client, algorithm, rate_limit, window_size,
                           category="api", identifier="endpoint", password="test-pass"):
    service_id, api_key, admin_id = create_service_via_api(client, "test-svc", password)
    create_rule_via_api(client, api_key, service_id, category, identifier,
                        rate_limit, window_size, algorithm)
    return service_id, api_key, admin_id
