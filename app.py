import eventlet
eventlet.monkey_patch()  # <-- Add this before all other imports
from pymongo import MongoClient
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import bcrypt
from bson import ObjectId
from datetime import datetime, timedelta
from pymongo import DESCENDING



app = Flask(__name__)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*") # Ensure eventlet is used correctly

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
data_recordings = db['dataRecordings']
notifications = db['UserNotif']


from datetime import datetime, timedelta

@socketio.on("get-data")
def handle_get_data(data):
    try:
        user_id = data.get("user_id")
        selected_date = data.get("date")
        page = int(data.get("page", 1))
        limit = 10  

        if not user_id or not selected_date:
            socketio.emit("data-response", {"success": False, "error": "Missing user_id or date"})
            return

        start_date = datetime.strptime(selected_date, "%Y-%m-%d")
        end_date = start_date + timedelta(days=1)  # Query data within the selected date range

        print(f"Fetching records for user_id={user_id} from {start_date} to {end_date}")  # Debug log

        records = list(data_recordings.find(
            {"user_id": user_id, "timestamp": {"$gte": start_date, "$lt": end_date}}
        ).sort("timestamp", -1)
        .skip((page - 1) * limit)
        .limit(limit))

        data = [{"id": str(record["_id"]), "temperature": record.get("temperature"), "humidity": record.get("humidity"), "timestamp": record["timestamp"].isoformat()} for record in records]

        print(f"Records found: {len(data)}")  # Debug log

        socketio.emit("data-response", {"success": True, "data": data})
    except Exception as e:
        print(f"Error fetching data: {str(e)}")  # Debug log
        socketio.emit("data-response", {"success": False, "error": str(e)})


@socketio.on("request_notifications")
def send_notifications(data):
    """Send paginated notifications for a specific user."""
    user_id = data.get("user_id")
    page = data.get("page", 1)  # Default to page 1
    per_page = 10  # Fetch 10 notifications at a time

    if not user_id:
        return

    # Query the database for the user's notifications
    notifications_cursor = notifications.find({"user_id": user_id}).sort("timestamp", DESCENDING).skip((page - 1) * per_page).limit(per_page)
    
    notifications_list = [
        {
            "id": str(notification["_id"]),
            "title": notification["title"],
            "message": notification["message"],
            "recommendation": notification["recommendation"],
            "timestamp": notification["timestamp"].isoformat(),
        }
        for notification in notifications_cursor
    ]

    # Check if there are more notifications
    total_notifications = notifications.count_documents({"user_id": user_id})
    has_more = (page * per_page) < total_notifications

    # Emit the paginated notifications
    socketio.emit("latest_notifications", {
        "notifications": notifications_list,
        "page": page,
        "has_more": has_more,
    }, room=request.sid)

    print(f"📡 Sent {len(notifications_list)} notifications (Page {page}) to user {user_id}")
    

@socketio.on("request_latest_data")
def send_latest_data(data):
    """Send the latest temperature & humidity for a specific user."""
    user_id = data.get("user_id")
    if not user_id:
        return

    latest_record = data_recordings.find_one({"user_id": user_id}, sort=[("timestamp", -1)])

    if latest_record:
        socketio.emit("latest_sensor_data", {
            "user_id": user_id,
            "temperature": latest_record["temperature"],
            "humidity": latest_record["humidity"],
            "timestamp": latest_record["timestamp"].isoformat()  # Convert datetime to string
        }, room=request.sid)
        print(f"📡 Sent latest sensor data for user {user_id}")

@socketio.on("temp_humi_update")
def fetch_temp_humi(data):
    user_id = data.get("user_id")
    socketio.emit("fetch_temp_humi", {"user_id": user_id})

@socketio.on("notif_update")
def fetch_new_notif(data):
    user_id = data.get("user_id")

    if not user_id:
        return

    # Fetch latest notifications for the user
    notifications_cursor = notifications.find({"user_id": user_id}).sort("timestamp", DESCENDING).limit(10)

    notifications_list = [
        {
            "id": str(notification["_id"]),
            "title": notification.get("title", "No Title"),
            "message": notification.get("message", "No Message"),
            "recommendation": notification.get("recommendation", "No Recommendation"),
            "timestamp": notification["timestamp"].isoformat(),
        }
        for notification in notifications_cursor
    ]

    # Emit the correct format
    socketio.emit("fetch_new_notif", {
        "user_id": user_id,
        "notifications": notifications_list,
    })
    print(f"📡 Sent {len(notifications_list)} new notifications to user {user_id}")

@socketio.on('device_status_update')
def handle_device_status_update(data):
    user_id = data.get('user_id')
    message = data.get('message')

    socketio.emit('status_notification', {
            'user_id': user_id, 
            'message': message,
            'screen': 'Notification'  
        })

    print(f"Received status update for user_id {user_id}: {message}")

@socketio.on('check_and_connect_device')
def handle_device_check_and_connect(data):
    device_name = data.get('deviceName')
    user_id = data.get('uid')
    start_date = data.get('start_date')

    print(f"Received device name: {device_name}")
    print(f"Received User: {user_id}")
    print(f"Received Date: {start_date}")
    
    # Search for the device in the collection
    device = collection.find_one({"device_name": device_name})
    if device:
        device_id = str(device.get('_id'))
        current_connection_status = device.get('connection')

        if current_connection_status == "connected":
            # Emit a response indicating the device is already paired
            socketio.emit('response', {
                'success': False,
                'message': 'Device is already paired with another device',
                'connection': 'connected',
                'deviceId': device_id
            })
            print(f"Device {device_name} is already paired with another device.")
            return

        # Update the device status to 'online' and connection to 'connected'
        collection.update_one(
            {"_id": ObjectId(device_id)},
            {"$set": {"connection": "connected"}}
        )
        print('Device updated and saved!')

        # Save the device ID in the UserDevices collection
        user_device = user_devices.find_one({"device_id": device_id})
        if not user_device:
            # If no entry exists, insert a new document
            user_devices.insert_one({
                "user_id": user_id,
                "deviceId": device_id,
                "start_date": start_date
            })
            print(f"New user device entry created for user_id: {user_id}")
        else:
            print(f"User device entry already exists for user_id: {user_id}")

        # Emit a success response with the updated status and device ID
        socketio.emit('response', {
            'success': True,
            'message': 'Device Found',
            'connection': 'connected',
            'deviceId': device_id
        })
        socketio.emit("set_to_offline")

    else:
        # Emit a failure response if the device is not found
        socketio.emit('response', {
            'success': False,
            'message': 'Device Not Found',
            'status': 'offline',
            'deviceId': None
        })


@socketio.on('disconnect_device')
def disconnect_device(data):
    device_id = data.get('deviceId')

    if not device_id:
        print("No device ID provided for disconnect.")
        return socketio.emit('device_disconnected_response', {
            'success': False,
            'message': 'Device ID is required'
        })

    # Find the device by its ID in the database
    device = collection.find_one({"_id": ObjectId(device_id)})

    if not device:
        print(f"Device with ID {device_id} not found.")
        return socketio.emit('device_disconnected_response', {
            'success': False,
            'message': 'Device not found'
        })

    user_devices.delete_one({"deviceId": device_id})
    print(f"Device {device_id} removed from UserDevices collection.")

    collection.update_one(
        {"_id": ObjectId(device_id)},
        {"$set": {"connection": "disconnected"}}
    )

    # Remove from connected devices if present
    device_name = device.get("device_name")
    sid_to_remove = None
    for sid, name in connected_devices.items():
        if name == device_name:
            sid_to_remove = sid
            break

    if sid_to_remove:
        connected_devices.pop(sid_to_remove, None)

    print(f"Device {device_name} disconnected successfully.")

    # Emit response to client
    socketio.emit('device_disconnected_response', {
        'success': True,
        'message': 'Device disconnected successfully',
        'deviceId': device_id
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

connected_devices = {}

@app.route('/')
def index():
    return "<h1>Welcome to the Flask Index Page!</h1>"
    
@socketio.on('connect')
def handle_connect():
    print("A device connected.")
    print("Connected devices:", connected_devices)
    socketio.emit("set_to_offline")
    
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
        socketio.emit("set_to_offline")
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


