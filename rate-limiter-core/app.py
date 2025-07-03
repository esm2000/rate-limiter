from datetime import datetime, timezone
from flask import Flask, jsonify, request
from flask.json.provider import DefaultJSONProvider
from werkzeug.exceptions import Conflict

from service import create_service, renew_api_token, get_service_info, update_service
from user import create_user, get_user_info, update_user

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

@app.route('/service', methods=['GET', 'POST', 'PUT'])
def handle_service_request():
    auth_header = request.headers.get("Authorization")
    data = request.get_json()
    try:
        if request.method == 'POST':
            service_id, api_key, admin_id = create_service(
                data.get("service_name"),
                data.get("admin_password")
            )
            return jsonify({
                "message": "Service created successfully",
                "service_id": service_id,
                "service_name": data.get("service_name"),
                "api_key": api_key,
                "admin_user_id": admin_id
            }), 201
        elif request.method == 'PUT':
            update_service(
                auth_header,
                data.get("service_id"),
                data.get("new_service_name")
            )
            return jsonify({
                "message": "Service updated successfully",
                "service_id": data.get("service_id"),
                "service_name": data.get("new_service_name")
            })
        elif request.method == 'GET':
            service_name, creation_time, api_key_expiration_time = get_service_info(auth_header, data.get("service_id"))
            return jsonify({
                "service_id": data.get("service_id"),
                "service_name": service_name,
                "creation_time": creation_time,
                "api_key_expiration_time": api_key_expiration_time
            }), 200
    except Conflict as e:
        return jsonify({"error": str(e)}), 400

@app.route('/service/<string:service_id>/token/rotate', methods=['POST'])
def handle_api_token_renewal(service_id):
    data = request.get_json()

    token = renew_api_token(
        service_id,
        data.get("user_id"),
        data.get("password")
    )

    return jsonify({
        "message": f"Successfully set new API token for service {service_id}",
        "token": token
        }), 200

@app.route('/user', methods=['GET', 'POST', 'PUT'])
def handle_user_endpoint():
    auth_header = request.headers.get("Authorization")
    data = request.get_json()
    service_id = data.get("service_id")
    user_id = data.get("user_id")
    password = data.get("password")
    new_password = data.get("new_password")
    is_admin = data.get("is_admin")
    
    if request.method == 'POST':
        user_id = create_user(auth_header, service_id, is_admin, password)
        return jsonify({
            "message": "User created successfully",
            "service_id": service_id,
            "user_id": user_id,
            # is_admin can be None
            "is_admin": True if is_admin else False
        }), 201
    elif request.method == 'PUT':
        update_user(auth_header, service_id, user_id, password, new_password)
        return jsonify({
            "message": "User updated successfully"
        })
    elif request.method == 'GET':
        service_id, is_admin, creation_time = get_user_info(auth_header, service_id, user_id, password)
        return jsonify({
            "user_id": user_id,
            "service_id": service_id,
            "is_admin": is_admin,
            "creation_time": creation_time
        }), 200
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)