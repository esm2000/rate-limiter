from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask.json.provider import DefaultJSONProvider
import requests
from werkzeug.exceptions import BadRequest, InternalServerError

from rule import create_rule, get_rule_info, update_rule, delete_rule
from service import create_service, delete_service, get_service_info, renew_api_token, update_service
from limiter import check_if_request_is_allowed, increment_rate_limit_usage
from user import create_user, delete_user, get_user_info, update_user

class UTCJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, datetime):
            if o.tzinfo is None:
                o = o.astimezone()
            o_utc = o.astimezone(timezone.utc)
            return o_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        return super().default(o)

app = Flask(__name__)
app.json_provider_class = UTCJSONProvider
app.json = app.json_provider_class(app)

@app.route('/', methods=['GET'])
def default():
    return 'rate-limiter-core'

@app.route('/service', methods=['POST'])
def handle_service_creation():
    data = request.get_json()
    service_name = data.get("service_name")
    admin_password = data.get("admin_password")
    try:
        service_id, api_key, admin_id = create_service(
            service_name,
            admin_password
        )
        return jsonify({
            "message": "Service created successfully",
            "service_id": service_id,
            "service_name": service_name,
            "api_key": api_key,
            "admin_user_id": admin_id
        }), 201
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/service/<string:service_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_service_request(service_id):
    auth_header = request.headers.get("Authorization")
    if request.method != 'GET':
        data = request.get_json()
        new_service_name = data.get("new_service_name")
    try:
        if request.method == 'GET':
            service_name, creation_time, api_key_expiration_time = get_service_info(auth_header, service_id)
            return jsonify({
                "service_id": service_id,
                "service_name": service_name,
                "creation_time": creation_time,
                "api_key_expiration_time": api_key_expiration_time
            }), 200
        elif request.method == 'PUT':
            update_service(
                auth_header,
                service_id,
                new_service_name
            )
            return jsonify({
                "message": "Service updated successfully",
                "service_id": service_id,
                "service_name": new_service_name
            })
        elif request.method == 'DELETE':
            delete_service(auth_header, service_id)
            return jsonify({
                "message": "Service deleted successfully"
            })
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/service/<string:service_id>/token/rotate', methods=['POST'])
def handle_api_token_renewal(service_id):
    data = request.get_json()
    user_id = data.get("user_id")
    password = data.get("password")
    try:
        token = renew_api_token(
            service_id,
            user_id,
            password
        )

        return jsonify({
            "message": f"Successfully set new API token for service {service_id}",
            "token": token
            }), 200
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/user', methods=['POST'])
def handle_user_creation():
    auth_header = request.headers.get("Authorization")
    data = request.get_json()
    service_id = data.get("service_id")
    password = data.get("password")
    is_admin = data.get("is_admin")
    
    try:
        user_id = create_user(auth_header, service_id, is_admin, password)
        return jsonify({
            "message": "User created successfully",
            "service_id": service_id,
            "user_id": user_id,
            # is_admin can be None
            "is_admin": True if is_admin else False
        }), 201
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500
    
    
@app.route('/user/<string:user_id>', methods=['GET', 'PUT', 'DELETE'])
def handle_user_request(user_id):
    auth_header = request.headers.get("Authorization")
    data = request.get_json()
    service_id = data.get("service_id")
    password = data.get("password")
    new_password = data.get("new_password")
    is_admin = data.get("is_admin")
    try:
        if request.method == 'GET':
            service_id, is_admin, creation_time = get_user_info(auth_header, service_id, user_id, password)
            return jsonify({
                "user_id": user_id,
                "service_id": service_id,
                "is_admin": is_admin,
                "creation_time": creation_time
            }), 200
        elif request.method == 'PUT':
            update_user(auth_header, service_id, user_id, password, new_password)
            return jsonify({
                "message": "User updated successfully"
            })
        elif request.method == 'DELETE':
            delete_user(auth_header, user_id, service_id)
            return jsonify({
                "message": f"User deleted successfully"
            })
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rule", methods=["POST"])
def handle_rule_creation():
    auth_header = request.headers.get("Authorization")
    
    data = request.get_json()
    domain = data.get("domain")
    category = data.get("category")
    identifier = data.get("identifier")
    rate_limit = data.get("rate_limit")
    window_size = data.get("window_size")
    algorithm = data.get("algorithm")

    try:
        create_rule(
            auth_header,
            domain,
            category,
            identifier,
            window_size,
            rate_limit,
            algorithm
        )
        return jsonify({
            "message": "Rule created successfully",
            "domain": domain,
            "category": category,
            "identifier": identifier,
            "window_size": window_size,
            "rate_limit": rate_limit,
            "algorithm": algorithm
        }), 201
    except InternalServerError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rule", methods=["GET", "PUT", "DELETE"])
def handle_rule_request():
    auth_header = request.headers.get("Authorization")

    data = request.get_json()
    domain = data.get("domain")
    category = data.get("category")
    identifier = data.get("identifier")
    window_size = data.get("window_size")
    rate_limit = data.get("rate_limit")
    algorithm = data.get("algorithm")

    if request.method == "GET":
        window_size, rate_limit, algorithm = get_rule_info(
            auth_header,
            domain,
            category,
            identifier
        )
        return jsonify({
            "domain": domain,
            "category": category,
            "identifier": identifier,
            "window_size": window_size,
            "rate_limit": rate_limit,
            "algorithm": algorithm
        })
    elif request.method == "PUT":
        update_rule(
            auth_header,
            domain,
            category,
            identifier,
            window_size,
            rate_limit,
            algorithm
        )
        return jsonify({
            "message": "Rule updated successfully"
        })
    elif request.method == "DELETE":
        delete_rule(
            auth_header,
            domain,
            category,
            identifier
        )
        return jsonify({
            "message": "Rule deleted successfully"
        })
    
@app.route("/redirect", methods=["POST"])
def redirect():
    data = request.get_json()
    domain = data.get("domain")
    category = data.get("category")
    identifier = data.get("identifier")
    redirect_url = data.get("redirect_url")
    redirect_method = data.get("redirect_method")
    redirect_params = data.get("redirect_params") or {}
    redirect_args = data.get("redirect_args") or {}
    user_id = data.get("user_id")
    password = data.get("password")

    current_time = datetime.now(timezone.utc)

    # TODO: implement rate limiting algorithms within this function.
    #       use Redis cache to store information for user, domain, category, identifier combination.
    #       create separate throttle module for this
    is_allowed, is_leaking_bucket = check_if_request_is_allowed(
        domain,
        category,
        identifier,
        user_id,
        password,
        current_time
    )

    if redirect_method.upper() not in ["GET", "OPTIONS", "HEAD", "POST", "PUT", "PATCH", "DELETE"]:
        raise BadRequest("Limit redirect_method input to GET, OPTIONS, HEAD, POST, PUT, PATCH, or DELETE.")
    
    if not isinstance(redirect_args, dict):
        raise BadRequest("Request arguments for redirect are malformed")
    
    if not isinstance(redirect_params, dict) :
        raise BadRequest("Request URL parameters for redirect are malformed")

    if not is_allowed:
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    try:
        if not is_leaking_bucket:
            response = requests.request(
                method=redirect_method.upper(),
                url=redirect_url,
                params=redirect_params,
                json=redirect_args,
                timeout=30
            )
        else:
            pass

        # TODO: implement
        increment_rate_limit_usage(domain, category, identifier, user_id, password, current_time)

        return jsonify({
            "status": response.status_code,
            "response": response.text
        })
    except requests.RequestException as e:
      return jsonify({"error": str(e)}), 502

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)