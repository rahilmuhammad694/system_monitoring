import socket
import webbrowser
import os
import stat
import time
import threading
import json
import os
import base64
import shutil
import certifi
from pymongo import MongoClient
from waitress import serve
from datetime import datetime
from collections import deque
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template_string, request, redirect, session, send_from_directory, send_file

# -------------------------------
# CONFIG
# -------------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# -------------------------------
# DATABASE (MongoDB)
# -------------------------------
client = MongoClient(
    "mongodb+srv://rahilmuhammad694:bvlY5LdqFIZA71to@cluster0.vz12nrc.mongodb.net/monitoring_system?retryWrites=true&w=majority",
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=5000
)

try:
    client.server_info()  # Force connection
    print("✅ MongoDB Connected")
except Exception as e:
    print("❌ MongoDB Connection Failed:", e)

# ✅ MISSING LINE (VERY IMPORTANT)
db = client["monitoring_system"]

logs_collection = db["logs"]
clients_collection = db["clients"]
alerts_collection = db["alerts"]

SAVE_DIRECTORY = os.path.join(BASE_DIR, "client_data")
RECYCLE_DIRECTORY = os.path.join(BASE_DIR, "deleted_clients")



# -------------------------------
# RISK SYSTEM
# -------------------------------
def update_risk(client, message):
    message = message.lower()

    if client not in risk_data:
        risk_data[client] = 0

    if "usb inserted" in message:
        risk_data[client] += 5

    if "restricted application" in message:
        risk_data[client] += 3


def add_activity(message):
     timestamp = datetime.now().strftime("%H:%M:%S")
     activity_log.appendleft(f"[{timestamp}] {message}")


def add_alert(message):
    timestamp = datetime.now()

    alerts.appendleft(f"[{timestamp.strftime('%H:%M:%S')}] {message}")

    alerts_collection.insert_one({
        "message": message,
        "timestamp": timestamp
    })


def get_risk_level(score):
    if score >= 7:
        return "HIGH", "danger"
    elif score >= 3:
        return "MEDIUM", "warning"
    else:
        return "LOW", "success"

os.makedirs(SAVE_DIRECTORY, exist_ok=True)
os.makedirs(RECYCLE_DIRECTORY, exist_ok=True)


# RISK STORAGE
# -------------------------------
risk_data = {}
# -------------------------------

activity_log = deque(maxlen=100)


# -------------------------------
# REAL TIME ALERT STORAGE
# -------------------------------
alerts = deque(maxlen=20)



# -------------------------------
# FEATURE SETTINGS
# -------------------------------
FEATURES = {
    "restricted_apps": True,
    "screenshot_capture": True,
    "auto_refresh": True,
    "usb_detection":True
}


# -------------------------------
# SOCKET SERVER
# -------------------------------
class MonitoringServer:
    def __init__(self, host="0.0.0.0", port=5000): 
        self.server_host = host
        self.server_port = port
        self.client_names = {}

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.server_host, self.server_port))
        server_socket.listen(5)

        print("Monitoring Server Started")
        print(f"Listening on {self.server_host}:{self.server_port}")

        while True:
            client_socket, client_address = server_socket.accept()
            try:
                identity_data = client_socket.recv(1024).decode("utf-8")
                identity = json.loads(identity_data)
                hostname = identity.get("hostname", "unknown")
                username = identity.get("username", "unknown")
                client_id = f"{hostname}_{username}"
            except:
                client_id = f"{client_address[0]}_{client_address[1]}"

            self.client_names[client_socket] = client_id
            thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()

    def handle_client(self, client_socket, client_address):
        buffer = ""
        client_id = self.client_names.get(
        client_socket,
        f"{client_address[0]}_{client_address[1]}"
)
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                buffer += data.decode("utf-8")

                while "\nEND\n" in buffer:
                    message, buffer = buffer.split("\nEND\n", 1)
                    self.process_message(message, client_id)
        finally:
            client_socket.close()

    def process_message(self, message, client_id):
        try:
            data = json.loads(message)
            clients_collection.update_one(
                {"client_id": client_id},
                {"$set": {
                    "last_seen": datetime.now(),
                    "system_info": data.get("system_info", {})
                }},
                upsert=True
            )
            log_text = data.get("logs", "")
            event_text = data.get("event", "")
            log_text = log_text.lower()
            event_text = event_text.lower()

            if "restricted application detected" in log_text:
                add_activity(f"{client_id} Restricted Application Opened")
                update_risk(client_id, log_text)
                add_alert(f"{client_id} Restricted Application Detected")


            if "usb inserted" in log_text or "usb inserted" in event_text:
                add_activity(f"{client_id} USB Inserted")
                update_risk(client_id, "usb inserted")
                add_alert(f"{client_id} USB Device Inserted")
            
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

            client_folder = os.path.join(
                SAVE_DIRECTORY,
                client_id
            )

            os.makedirs(client_folder, exist_ok=True)

            log_file = os.path.join(client_folder, "logs.txt")

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("\n==============================\n")
                f.write(f"Received at: {timestamp}\n\n")

                if "system_info" in data:
                    f.write("---- SYSTEM INFO ----\n")
                    for k, v in data["system_info"].items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n")

                if "logs" in data:
                    f.write("---- LOGS ----\n")
                    f.write(data["logs"])
                    f.write("\n")
                    update_risk(client_id, data["logs"])
                

            if FEATURES["usb_detection"] and "usb_inserted" in data:
                add_activity(f"{client_id} USB Inserted")


            if event_text:
                add_activity(f"{client_id} {event_text}") 
                update_risk(client_id, event_text)

            if FEATURES["screenshot_capture"] and data.get("screenshot"):
                screenshot_bytes = base64.b64decode(data["screenshot"])
                add_activity(f"{client_id} Screenshot received")
                add_alert(f"{client_id} Screenshot Captured")
                screenshot_path = os.path.join(
                    client_folder,
                    f"screenshot_{timestamp}.png"
                )
                with open(screenshot_path, "wb") as img:
                    img.write(screenshot_bytes)
                print("screenshot saved at:",screenshot_path)

            logs_collection.insert_one({
                "client_id": client_id,
                "timestamp": datetime.now(),
                "logs": data.get("logs", ""),
                "event": data.get("event", "")
            })    

        except Exception as e:
            print("Processing error:", e)

# -------------------------------
# AUTH
# -------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (request.form["username"] == ADMIN_USERNAME and
                check_password_hash(ADMIN_PASSWORD_HASH, request.form["password"])):
            activity_log.clear()
            session["logged_in"] = True
            return redirect("/dashboard")
        return "Invalid credentials"

    return """
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>
    <div class='container mt-5'>
    <div class='row justify-content-center'>
    <div class='col-md-4'>
    <div class='card shadow'>
    <div class='card-body'>
    <h4>Admin Login</h4>
    <form method='post'>
    <input class='form-control mb-3' name='username' placeholder='Username'>
    <input class='form-control mb-3' name='password' type='password' placeholder='Password'>
    <button class='btn btn-primary w-100'>Login</button>
    </form>
    </div></div></div></div></div>
    """

# -------------------------------
# DASHBOARD
# -------------------------------
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/")
    # ---------------- ANALYTICS ----------------
    total_clients = clients_collection.count_documents({})
    total_alerts = alerts_collection.count_documents({})

    high_risk = 0
    medium_risk = 0
    low_risk = 0

    for client in clients_collection.find():
        client_id = client.get("client_id")

        score = risk_data.get(client_id, 0)
        level, _ = get_risk_level(score)

        if level == "HIGH":
            high_risk += 1
        elif level == "MEDIUM":
            medium_risk += 1
        else:
            low_risk += 1
# ------------------------------------------
    
    
    clients = []
    now = datetime.now()

    for client in clients_collection.find():
        client_id = client.get("client_id")

        last_seen = client.get("last_seen", now)
        delta = (now - last_seen).seconds

        status = "Online" if delta < 15 else "Offline"

        clients.append((client_id, status))

    return render_template_string("""
<!doctype html>
<html>
<head>

{% if features.auto_refresh %}
<meta http-equiv="refresh" content="5">
{% endif %}

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

<style>

body{
background:#0f172a;
color:white;
font-family:system-ui;
}

.navbar{
background:#020617;
border-bottom:1px solid #1e293b;
}

.dashboard-title{
font-weight:600;
letter-spacing:1px;
}

.card{
background:#020617;
border:1px solid #1e293b;
color:white;
transition:0.3s;
}

.card:hover{
transform:translateY(-4px);
box-shadow:0 10px 25px rgba(0,0,0,0.5);
}

.activity-box{
background:#020617;
border:1px solid #1e293b;
font-family:monospace;
color:#38bdf8;
}

.client-card h5{
font-size:16px;
}

.badge{
font-size:12px;
}

.btn{
font-size:12px;
}

</style>

</head>

<body>

<nav class="navbar navbar-dark">
<div class="container-fluid">

<span class="navbar-brand dashboard-title">
🛡 Security Monitoring Dashboard
</span>

<div>

<div class="dropdown d-inline">

<a href="/settings" class="btn btn-outline-light btn-sm">
⚙ Settings
</a>

<div class="dropdown-menu dropdown-menu-end p-3"
style="min-width:250px;">

<form method="post" action="/toggle_feature">

<input type="hidden" name="feature" value="restricted_apps">

<div class="form-check form-switch">

<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.restricted_apps %}checked{% endif %}>

<label class="form-check-label">
Restricted App Detection
</label>

</div>

</form>


<form method="post" action="/toggle_feature">

<input type="hidden" name="feature" value="screenshot_capture">

<div class="form-check form-switch">

<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.screenshot_capture %}checked{% endif %}>

<label class="form-check-label">
Screenshot Capture
</label>

</div>

</form>


<form method="post" action="/toggle_feature">

<input type="hidden" name="feature" value="auto_refresh">

<div class="form-check form-switch">

<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.auto_refresh %}checked{% endif %}>

<label class="form-check-label">
Auto Refresh Dashboard
</label>

</div>

</form>

</div>
</div>

<a href="/logout" class="btn btn-danger btn-sm ms-2">
Logout
</a>

</div>
</div>
</nav>


<div class="container mt-4">
<!-- ANALYTICS CARDS -->
<div class="row mb-4">

<div class="col-md-3">
<div class="card text-center p-3">
<h6>👥 Total Clients</h6>
<h3>{{total_clients}}</h3>
</div>
</div>

<div class="col-md-3">
<div class="card text-center p-3">
<h6>⚠ Total Alerts</h6>
<h3>{{total_alerts}}</h3>
</div>
</div>

<div class="col-md-2">
<div class="card text-center p-3">
<h6>🔴 High Risk</h6>
<h3>{{high_risk}}</h3>
</div>
</div>

<div class="col-md-2">
<div class="card text-center p-3">
<h6>🟡 Medium Risk</h6>
<h3>{{medium_risk}}</h3>
</div>
</div>

<div class="col-md-2">
<div class="card text-center p-3">
<h6>🟢 Low Risk</h6>
<h3>{{low_risk}}</h3>
</div>
</div>

</div>                       

<!-- Activity Log -->

<div class="card mb-4 shadow">

<div class="card-header bg-dark">
Live Activity
</div>

<div class="card-body activity-box"
style="max-height:260px;overflow-y:auto">

{% if activity_log %}

{% for event in activity_log %}

<div>{{event}}</div>

{% endfor %}

{% else %}

<div class="text-secondary">
No activity yet
</div>

{% endif %}

</div>
</div>


<div class="row">

{% for client, status in clients %}

<div class="col-lg-3 col-md-4 mb-4">

<div class="card client-card shadow">

<div class="card-body">

<h5>

{{client}}

{% set score = risk_data.get(client,0) %}
{% set level,color = get_risk_level(score) %}

<span class="badge bg-{{color}} ms-2">

{{level}} ({{score}})

</span>

</h5>


<p>

Status

<span class="badge bg-{{'success' if status=='Online' else 'secondary'}}">

{{status}}

</span>

</p>


<div class="d-grid gap-2">

<a href="/view_logs/{{client}}" class="btn btn-primary btn-sm">

View Logs

</a>

<a href="/download_logs/{{client}}" class="btn btn-warning btn-sm">

Download Logs

</a>

<a href="/view_screenshots/{{client}}" class="btn btn-info btn-sm">

Screenshots

</a>

<form method="post"
action="/delete_client/{{client}}"
onsubmit="return confirm('Move this client data to recycle folder?');">

<button class="btn btn-danger btn-sm w-100">

Delete Client

</button>

</form>

</div>

</div>
</div>

</div>

{% endfor %}

</div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>

let lastAlert = "";

function checkAlerts(){

fetch("/get_alerts")
.then(res => res.json())
.then(data => {

if(data.alerts.length > 0){

let newest = data.alerts[0];

if(newest !== lastAlert){

lastAlert = newest;

showPopup(newest);

}

}

});

}

function showPopup(message){

let popup = document.createElement("div");

popup.style.position="fixed";
popup.style.bottom="20px";
popup.style.right="20px";
popup.style.background="#dc3545";
popup.style.color="white";
popup.style.padding="12px 20px";
popup.style.borderRadius="8px";
popup.style.boxShadow="0px 5px 20px rgba(0,0,0,0.5)";
popup.style.zIndex="9999";

popup.innerText = "⚠ " + message;

document.body.appendChild(popup);

setTimeout(()=>popup.remove(),4000);

}

setInterval(checkAlerts,3000);

</script>
</body>

</html>
""", clients=clients, features=FEATURES,risk_data=risk_data,get_risk_level=get_risk_level,activity_log=activity_log,total_clients=total_clients,total_alerts=total_alerts,high_risk=high_risk,medium_risk=medium_risk,low_risk=low_risk)

# -------------------------------
# SETTINGS PAGE
# -------------------------------
@app.route("/settings")
def settings():

    if not session.get("logged_in"):
        return redirect("/")

    return render_template_string("""

<!doctype html>
<html>
<head>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

<style>

body{
background:#0f172a;
color:white;
font-family:system-ui;
}

.card{
background:#020617;
border:1px solid #1e293b;
color:white;
}

</style>

</head>

<body>

<div class="container mt-5">

<h3 class="mb-4">
⚙ System Settings
</h3>

<div class="card shadow">
<div class="card-body">

<h5 class="mb-3">Monitoring Features</h5>
<hr>

<form method="post" action="/toggle_feature">
<input type="hidden" name="feature" value="restricted_apps">

<div class="form-check form-switch mb-3">
<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.restricted_apps %}checked{% endif %}>

<label class="form-check-label">
Restricted Application Detection
</label>
</div>
</form>


<form method="post" action="/toggle_feature">
<input type="hidden" name="feature" value="screenshot_capture">

<div class="form-check form-switch mb-3">
<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.screenshot_capture %}checked{% endif %}>

<label class="form-check-label">
Screenshot Capture
</label>
</div>
</form>


<form method="post" action="/toggle_feature">
<input type="hidden" name="feature" value="usb_detection">

<div class="form-check form-switch mb-3">
<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.usb_detection %}checked{% endif %}>

<label class="form-check-label">
USB Device Detection
</label>
</div>
</form>


<form method="post" action="/toggle_feature">
<input type="hidden" name="feature" value="auto_refresh">

<div class="form-check form-switch mb-3">
<input class="form-check-input"
type="checkbox"
onchange="this.form.submit()"
{% if features.auto_refresh %}checked{% endif %}>

<label class="form-check-label">
Auto Refresh Dashboard
</label>
</div>
</form>

<hr>

<a href="/dashboard" class="btn btn-primary">
Back to Dashboard
</a>

</div>
</div>

</div>

</body>
</html>

""", features=FEATURES)


@app.route("/toggle_feature", methods=["POST"])
def toggle_feature():
    if not session.get("logged_in"):
        return redirect("/")

    feature = request.form.get("feature")

    if feature in FEATURES:
        FEATURES[feature] = not FEATURES[feature]

    return redirect(request.referrer)
# -------------------------------
# RECYCLE (SOFT DELETE)
# -------------------------------
@app.route("/delete_client/<client>", methods=["POST"])
def delete_client(client):
    if not session.get("logged_in"):
        return redirect("/")
    if ".." in client or "/" in client:
        return "Invalid client"
    client_folder = os.path.join(SAVE_DIRECTORY, client)

    if os.path.exists(client_folder):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            recycled_name = f"{client}_{timestamp}"
            destination = os.path.join(RECYCLE_DIRECTORY, recycled_name)

            shutil.move(client_folder, destination)

            print(f"Moved {client} to recycle folder")

        except Exception as e:
            return f"Error moving client to recycle folder: {e}"

    return redirect("/dashboard")


# -------------------------------
# GET ALERTS (API)
# -------------------------------
@app.route("/get_alerts")
def get_alerts():
    if not session.get("logged_in"):
        return {"alerts": []}

    return {"alerts": list(alerts)}


# -------------------------------
# SEARCHABLE LOG VIEW
# -------------------------------
@app.route("/view_logs/<client>")
def view_logs(client):
    if not session.get("logged_in"):
        return redirect("/")
    if ".." in client or "/" in client:
        return "Invalid client"

    logs = logs_collection.find({"client_id": client})

    content = ""
    for log in logs:
        content += f"{log.get('timestamp','')} - {log.get('logs','')}\n"

    return render_template_string("""
<!doctype html>
<html>
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<script>
function filterLogs() {
    let input = document.getElementById("searchInput").value.toLowerCase();
    let lines = document.getElementById("logContent").innerText.split("\\n");
    let output = lines.filter(line => line.toLowerCase().includes(input));
    document.getElementById("filteredContent").innerText = output.join("\\n");
}
</script>
</head>
<body>
<div class="container mt-4">
<h3>Logs - {{client}}</h3>
<input id="searchInput" onkeyup="filterLogs()" class="form-control mb-3" placeholder="Search logs...">
<pre id="logContent" style="display:none;">{{content}}</pre>
<pre id="filteredContent" style="background:#f8f9fa; padding:15px;">{{content}}</pre>
<a href="/dashboard" class="btn btn-secondary mt-3">Back</a>
</div>
</body>
</html>
""", client=client, content=content)

# -------------------------------
# DOWNLOAD LOGS
# -------------------------------
@app.route("/download_logs/<client>")
def download_logs(client):
    if not session.get("logged_in"):
        return redirect("/")
    if ".." in client or "/" in client:
        return "Invalid client"

    log_path = os.path.join(SAVE_DIRECTORY, client, "logs.txt")
    if not os.path.exists(log_path):
        return "No logs available"

    return send_file(log_path, as_attachment=True)

# -------------------------------
# SCREENSHOTS
# -------------------------------
from urllib.parse import quote

@app.route("/view_screenshots/<path:client>")
def view_screenshots(client):
    if not session.get("logged_in"):
        return redirect("/")
    if ".." in client:
        return "Invalid client"

    folder = os.path.join(SAVE_DIRECTORY, client)

    if not os.path.exists(folder):
        return "Client folder not found"

    images = sorted(
    [f for f in os.listdir(folder) if f.lower().endswith(".png")],
    reverse=True)

    encoded_client = quote(client)

    html = """
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <div class="container mt-4">
    <h3>Screenshots</h3>
    <div class="row">
    """

    for img in images:
        html += f"""
        <div class='col-md-3'>
            <div class='card shadow mb-3'>
                <img src='/screenshots/{encoded_client}/{img}' class='card-img-top'>
            </div>
        </div>
        """

    html += """
    </div>
    <a href='/dashboard' class='btn btn-secondary mt-3'>Back</a>
    </div>
    """

    return html

from urllib.parse import unquote

@app.route("/screenshots/<path:client>/<filename>")
def serve_screenshot(client, filename):
    from urllib.parse import unquote

    client = unquote(client)
    filename = unquote(filename)

    if ".." in client or ".." in filename:
        return "Invalid path"

    folder = os.path.join(SAVE_DIRECTORY, client)

    if not os.path.exists(folder):
        return "Client folder not found"

    file_path = os.path.join(folder, filename)

    if not os.path.exists(file_path):
        return "Screenshot not found"

    return send_from_directory(folder, filename)
@app.route("/logout")
def logout():
    activity_log.clear()
    session.clear()
    return redirect("/")

# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    server = MonitoringServer()
    threading.Thread(target=server.start_server, daemon=True).start()

    # Small delay to allow Flask to initialize
    time.sleep(1)

    # Open browser automatically
    webbrowser.open("http://127.0.0.1:8000")

    serve(app, host="0.0.0.0", port=8000, threads=12,connection_limit=300)