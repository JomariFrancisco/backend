import eventlet
eventlet.monkey_patch()  # <-- Add this before all other imports
from pymongo import MongoClient
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import bcrypt
from bson import ObjectId


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)
app.config['JWT_SECRET_KEY'] = "a9f8b27c9d3e4f5b6c7d8e9f1029384756c7d8e9f1029384756a7b8c9d0e1f2"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 900  # 15 minutes
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 7 * 24 * 60 * 60  # 7 days
jwt = JWTManager(app)


client = MongoClient("mongodb+srv://jzfdgreat:oOQ6mZgq9bP10c0u@cluster0.fphp4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['JomsDB']
users_collection = db["UserInfo"]
collection = db['Device']
user_devices = db['UserDevices']



connected_devices = {}

@app.route('/')
def index():
    return "<h1>Welcome to the Flask Index Page!</h1>"
    
@socketio.on('connect')
def handle_connect():
    print("A device connected.")
    print("Connected devices:", connected_devices)

@socketio.on('disconnect')
def handle_disconnect():
    device_name = connected_devices.pop(request.sid, None)
    
    if device_name:
        print(f"Device {device_name} disconnected.")
        
        collection.update_one(
            {"device_name": device_name},
            {"$set": {"status": "offline"}}
        )
        print(f"Device {device_name} status set to 'offline'.")

    else:
        print("Device disconnected unexpectedly.")

    # Print the updated list of connected devices
    print("Connected devices:", connected_devices)

@app.route("/login-user", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if "users_collection" not in globals():
        print("users_collection is not defined in global scope!")
        return jsonify({"status": "error", "data": "Server error"}), 500

    print(f"Checking login for {email}")

    user = users_collection.find_one({"email": email})

    if not user:
        print("User not found")
        return jsonify({"status": "error", "data": "User not found"}), 404

    # Get the stored password from the database
    stored_password = user.get("password", "")

    if isinstance(stored_password, str):
        stored_password = stored_password.encode("utf-8")

    # Compare the passwords
    if not bcrypt.checkpw(password.encode("utf-8"), stored_password):
        print("Invalid password")
        return jsonify({"status": "error", "data": "Invalid password"}), 401

    # Create JWT token
    access_token = create_access_token(identity=str(user["_id"]))
    refresh_token = create_refresh_token(identity=str(user["_id"]))

    return jsonify({"status": "success", "access_token": access_token, "refresh_token": refresh_token}), 200

@app.route("/refresh-token", methods=["POST"])
@jwt_required(refresh=True)  
def refresh_token():
    user_id = get_jwt_identity()

    new_access_token = create_access_token(identity=user_id)

    new_refresh_token = create_refresh_token(identity=user_id)

    return jsonify({"access_token": new_access_token, "refresh_token": new_refresh_token}), 200

# Get User Data (Protected)
@app.route("/userdata", methods=["POST"])
@jwt_required()
def get_userdata():
    try:
        user_id = get_jwt_identity()

        if not user_id:
            print("No user ID found in token.")
            return jsonify({"status": "error", "data": "Invalid token"}), 401

        user = users_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            print("User not found")
            return jsonify({"status": "error", "data": "User not found"}), 404

        user_data = {
            "id": str(user["_id"]), 
            "name": user.get("name"),
            "email": user.get("email"),
            "profile_picture": user.get("profile_picture", "")  
        }

        return jsonify({"status": "ok", "data": user_data}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"status": "error", "data": "An error occurred"}), 500

@app.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Check if user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"status": "error", "data": "User Already Exists!"}), 400

    # Hash the password before storing
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert user into database
    user_id = users_collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_password
    }).inserted_id

    return jsonify({"status": "ok", "data": "User Created", "user_id": str(user_id)}), 201


@app.route('/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    user_email = data.get("email")  # Ensure email is sent in request
    new_name = data.get("name")
    new_profile_picture = data.get("profile_picture")

    if not user_email:
        return jsonify({"status": "error", "message": "Email is required"}), 400

    users_collection.update_one(
        {"email": user_email}, 
        {"$set": {"name": new_name, "profile_picture": new_profile_picture}}
    )

    return jsonify({"status": "ok", "message": "Profile updated successfully!"})


@socketio.on('register_device')
def register_device(data):
    device_name = data.get('deviceName')
    
    if device_name:
        connected_devices[request.sid] = device_name
        
        device = collection.find_one({"device_name": device_name})
        if not device:
            collection.insert_one({
                "device_name": device_name,
                "status": "online",
            })
            print(f"New device {device_name} added to the collection with status 'online'.")
        else:
            collection.update_one(
                {"device_name": device_name},
                {"$set": {"status": "online"}}
            )
            print(f"Device {device_name} status updated to 'online'.")

        print(f"Device {device_name} registered.")
        print("Connected devices:", connected_devices)

@socketio.on('check_and_connect_device')
def handle_device_check_and_connect(data):
    device_name = data.get('deviceName')
    user_id = data.get('uid')

    print(f"Received device name: {device_name}")
    print(f"Received User: {user_id}")

    device = collection.find_one({"device_name": device_name})
    if device:
        device_id = str(device.get('_id'))
        current_connection_status = device.get('connection')

        if current_connection_status == "connected":
            socketio.emit('response', {
                'success': False,
                'message': 'Device is already paired with another device',
                'status': 'online',
                'connection': 'connected',
                'deviceId': device_id
            })
            print(f"Device {device_name} is already paired with another device.")
            return

        collection.update_one(
            {"_id": ObjectId(device_id)},
            {"$set": {"status": "online", "connection": "connected"}}
        )
        print('Device updated and saved!')

        user_device = user_devices.find_one({"device_id": device_id})
        if not user_device:
            user_devices.insert_one({
                "user_id": user_id,
                "deviceId": device_id
            })
            print(f"New user device entry created for user_id: {user_id}")
        else:
            print(f"User device entry already exists for user_id: {user_id}")

        socketio.emit('response', {
            'success': True,
            'message': 'Device Found',
            'status': 'online',
            'connection': 'connected',
            'deviceId': device_id
        })
    else:
        socketio.emit('response', {
            'success': False,
            'message': 'Device Not Found',
            'status': 'offline',
            'deviceId': None
        })

@socketio.on('fetch_user_devices')
def fetch_user_devices(data):
    user_id = data.get('uid')
    userdevices = user_devices.find({"user_id": user_id})
    devices = []

    for userdevice in userdevices:
        device_id = userdevice.get("deviceId")
        device = collection.find_one({"_id": ObjectId(device_id)})
        if device:
            devices.append({
                "deviceId": str(device["_id"]),  # Convert ObjectId to string
                "deviceName": device.get("device_name"),
                "status": device.get("status", "Unknown")
            })

    print(devices)  
    socketio.emit('user_devices_response', {"devices": devices})

    
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)


