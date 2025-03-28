from flask import Flask, jsonify, request
from service import create_service, get_service_info, update_service
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
            update_service()
        elif request.method == 'GET':
            get_service_info()
    except Conflict as e:
        return jsonify({"error": str(e)}), 400

@app.route('/user', methods=['GET', 'POST', 'PUT'])
def handle_user_endpoint():
    if request.method == 'POST':
        create_user()
    elif request.method == 'PUT':
        update_user()
    elif request.method == 'GET':
        get_user_info()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)