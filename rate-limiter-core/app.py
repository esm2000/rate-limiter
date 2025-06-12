from flask import Flask, jsonify, request
from service import create_service, renew_api_token, get_service_info, update_service
from user import create_user, get_user_info, update_user
from werkzeug.exceptions import Conflict

app = Flask(__name__)

@app.route('/', methods=['GET'])
def default():
    return 'rate-limiter-core'

@app.route('/service', methods=['GET', 'POST', 'PUT'])
def handle_service_request():
    try:
        if request.method == 'POST':
            data = request.get_json()
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
            # TODO: REMEMBER TO ENFORCE API TOKEN FOR ADMIN
            update_service()
        elif request.method == 'GET':
            # TODO: REMEMBER TO ENFORCE API TOKEN FOR ADMIN
            get_service_info()
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
# TODO: REMEMBER TO ENFORCE API TOKEN FOR ADMIN
#       But no API token enforcement is needed for a user updating or retrieving their own information
def handle_user_endpoint():
    auth_header = request.headers.get("Authorization")
    data = request.get_json()
    service_id = data.get("service_id")
    user_id = data.get("user_id")
    password = data.get("password")
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
        # TODO: either auth_header (to signal admin) or user_id + password of user needs to be provided
        update_user(auth_header, service_id, user_id, password)
    elif request.method == 'GET':
        # TODO: either auth_header (to signal admin) or user_id + password of user needs to be provided
        get_user_info(auth_header, service_id, user_id, password)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)