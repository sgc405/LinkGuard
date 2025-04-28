from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for
from urllib.parse import urlparse
import tldextract
import re
from google.cloud import dialogflow
import json
import os
import datetime
import pdfkit
import hashlib
import sqlite3
import requests   # new – used to verify captcha
from google.oauth2 import service_account
print("Starting LinkGuard Scanner...")
app = Flask(__name__)
app.secret_key = "your-secret-key-here"  # Replace with a secure key in production

#Sqlite database

#Sqlite database
def init_db(): 
    print("Initializing database...")
    conn = sqlite3.connect("users.db")  # Use a single database for both admins and users
    cursor = conn.cursor()
    # Create admins table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)
    # Check if there are any admins, if not, create a default admin
    cursor.execute("SELECT COUNT(*) FROM admins")
    if cursor.fetchone()[0] == 0:
        default_username = "admin"
        default_password = "password123"
        hashed_password = hashlib.sha256(default_password.encode()).hexdigest()
        cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (default_username, hashed_password))
    
    # Create users table for regular users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)
    # Check if there are any users, if not, create a default user for testing
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_user = "user1"
        default_user_password = "userpass123"
        hashed_user_password = hashlib.sha256(default_user_password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (default_user, hashed_user_password))
    
    conn.commit()
    conn.close()
    print("Database initialization completed")

# Initialize the database
init_db()  # Call the function once here
# Initialize the database


# Load admin credentials from SQLite
def load_admin(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM admins WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Save a new admin to SQLite
def save_admin(username, hashed_password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()


# Load user credentials from SQLite
def load_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Save a new user to SQLite
def save_user(username, hashed_password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()

# Load all users from SQLite
def load_all_users():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = [row[0] for row in cursor.fetchall()]
    conn.close()
    return users

# Delete a user and their scan history
def delete_user(username):
    # Delete from users table
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    # Delete from user-specific scan history
    user_history = load_user_scan_history()  # Fixed typo: added parentheses to call the function
    if username in user_history:
        del user_history[username]
        with open("user_scan_history.json", "w") as f:
            json.dump(user_history, f, indent=2)

    # Delete user's scans from global history
    global_history = load_scan_history()
    global_history = [entry for entry in global_history if entry.get("username") != username]
    with open("scan_history.json", "w") as f:
        json.dump(global_history, f, indent=2)

# Feedback management
def load_feedback():
    feedback_file = "feedback.json"
    try:
        with open(feedback_file, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_feedback(entry):
    feedback_file = "feedback.json"
    feedback = load_feedback()
    feedback.append(entry)
    with open(feedback_file, "w") as f:
        json.dump(feedback, f, indent=2)

# Scan history management
def load_scan_history():
    history_file = "scan_history.json"
    try:
        with open(history_file, "r") as f:
            history = json.load(f)
            # Validate that history is a list of dictionaries
            if not isinstance(history, list):
                return []
            # Filter out invalid entries
            valid_history = []
            for entry in history:
                if isinstance(entry, dict) and "risk_category" in entry:
                    valid_history.append(entry)
            return valid_history
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# User-specific scan history management
def load_user_scan_history():
    user_history_file = "user_scan_history.json"
    try:
        with open(user_history_file, "r") as f:
            history = json.load(f)
            if not isinstance(history, dict):
                return {}
            return history
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_user_scan_history(username, url, risk_category, threat_type, findings, threat_report, source="scan"):
    user_history_file = "user_scan_history.json"
    user_history = load_user_scan_history()
    
    # Initialize user's history if it doesn't exist
    if username not in user_history:
        user_history[username] = []
    
    # Create new scan entry
    new_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "risk_category": risk_category,
        "threat_type": threat_type,
        "findings": findings,
        "threat_report": threat_report,
        "source": source
    }

    # Add new entry to user's history
    user_history[username].insert(0, new_entry)  # Add to the beginning (most recent first)
    
    # Keep only the last 10 entries for the user
    if len(user_history[username]) > 10:
        user_history[username] = user_history[username][:10]
    
    # Save updated user history
    try:
        with open(user_history_file, 'w') as f:
            json.dump(user_history, f, indent=2)
    except Exception as e:
        print(f"Error saving user_scan_history.json: {e}")
        raise

def save_scan_history(url, risk_category, threat_type, findings, threat_report, source="scan", username=None):
    history_file = "scan_history.json"
    new_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "risk_category": risk_category,
        "threat_type": threat_type,
        "findings": findings,
        "threat_report": threat_report,
        "source": source,
        "username": username  # Include the username for admin tracking
    }

    # Load existing history
    history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
            if not isinstance(history, list):
                history = []
            print(f"Loaded {len(history)} entries from scan_history.json")  # Debug log
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}, initializing empty history")  # Debug log
            history = []

    # Add new entry to the beginning (most recent first)
    history.insert(0, new_entry)
    print(f"Appended new entry, total entries: {len(history)}")  # Debug log

    # Keep only the last 100 entries
    if len(history) > 100:
        history = history[:100]

    # Save updated history
    try:
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
        print("Saved scan_history.json")  # Debug log
    except Exception as e:
        print(f"Error saving scan_history.json: {e}")  # Debug log
        raise  # Re-raise to be caught by the route's exception handler

# Ported PhishingDetector class
class PhishingDetector:
    def __init__(self):
        self.suspicious_terms = [
            "login", "secure", "verify", "account", "update", "bank", "free", "offer", "confirm",
            "phishing", "malware", "scam", "fraud", "password", "credential", "auth", "signin", "sign-in",
            "unwanted", "bill", "billing"
        ]
        self.max_url_length = 150  # Increased to reduce false positives
        self.max_subdomains = 3     # Increased to reduce false positives
        self.known_phishing_domains = ["testsafebrowsing", "phishingsite", "malicious.example"]
        self.known_safe_domains = ["google.com", "example.com", "wikipedia.org", "github.com"]
        self.suspicious_path_patterns = {
            "phishing": ["phishing"],
            "malware": ["malware", "malware_in_iframe", "image_small", "image_medium", "image_large", "dynamically_loaded_image", "css", "js"],
            "unwanted": ["unwanted"],
            "billing": ["trick_to_bill", "bill", "billing"]
        }
        self.known_safe_urls = set()
        self.known_unsafe_urls = set()
        self.load_feedback()

    def load_feedback(self):
        feedback = load_feedback()
        for entry in feedback:
            url = entry["url"]
            user_assessment = entry["user_assessment"]
            if user_assessment == "safe":
                self.known_safe_urls.add(url)
            elif user_assessment == "unsafe":
                self.known_unsafe_urls.add(url)

    def is_ip_based(self, hostname):
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        return bool(re.match(ip_pattern, hostname))

    def contains_risky_words(self, link):
        link_lower = link.lower()
        return any(term in link_lower for term in self.suspicious_terms)

    def has_excessive_subdomains(self, domain_info):
        subdomains = domain_info.subdomain.split(".")
        return len([s for s in subdomains if s]) > self.max_subdomains

    def is_url_too_long(self, link):
        return len(link) > self.max_url_length

    def contains_known_phishing_domain(self, domain):
        domain_lower = domain.lower()
        return any(phishing_domain in domain_lower for phishing_domain in self.known_phishing_domains)

    def contains_known_safe_domain(self, domain):
        domain_lower = domain.lower()
        return any(safe_domain in domain_lower for safe_domain in self.known_safe_domains)

    def lacks_https(self, scheme):
        return scheme.lower() != "https"

    def classify_threat(self, path):
        path_lower = path.lower()
        for threat_type, patterns in self.suspicious_path_patterns.items():
            if any(pattern in path_lower for pattern in patterns):
                return threat_type
        return None

    def evaluate_link(self, link):
        parsed = urlparse(link)
        domain_info = tldextract.extract(link)
        hostname = parsed.netloc
        scheme = parsed.scheme
        registered_domain = domain_info.registered_domain
        path = parsed.path

        # Detection criteria with weighted scoring
        findings = {
            "Uses IP Address": self.is_ip_based(hostname),        # Weight: 3 (high risk)
            "Risky Keywords": self.contains_risky_words(link),    # Weight: 1 (moderate risk)
            "Too Many Subdomains": self.has_excessive_subdomains(domain_info),  # Weight: 1
            "Excessive Length": self.is_url_too_long(link),       # Weight: 1
            "Known Phishing Domain": self.contains_known_phishing_domain(hostname),  # Weight: 4 (very high risk)
            "Known Safe Domain": self.contains_known_safe_domain(registered_domain),  # Weight: -3 (reduces risk)
            "Lacks HTTPS": self.lacks_https(scheme),              # Weight: 2 (moderate risk)
            "Suspicious Path": self.classify_threat(path) is not None  # Weight: 2
        }

        threat_type = self.classify_threat(path)

        # Weighted scoring
        risk_score = 0
        if findings["Uses IP Address"]:
            risk_score += 3
        if findings["Risky Keywords"]:
            risk_score += 1
        if findings["Too Many Subdomains"]:
            risk_score += 1
        if findings["Excessive Length"]:
            risk_score += 1
        if findings["Known Phishing Domain"]:
            risk_score += 4
        if findings["Known Safe Domain"]:
            risk_score -= 3  # Reduce risk for known safe domains
        if findings["Lacks HTTPS"]:
            risk_score += 2
        if findings["Suspicious Path"]:
            risk_score += 2

        # Incorporate user feedback as a weighted factor
        user_feedback = None
        if link in self.known_safe_urls:
            user_feedback = "Marked as Safe by User"
            risk_score -= 2  # Reduce risk, but don't override
        elif link in self.known_unsafe_urls:
            user_feedback = "Marked as Unsafe by User"
            risk_score += 2  # Increase risk, but don't override

        # Determine risk category based on score
        if risk_score >= 4:
            risk_category = "High"
        elif risk_score >= 2:
            risk_category = "Medium"
        else:
            risk_category = "Low"

        # Calculate safety grade (0-100)
        grade = 100 - (risk_score * 10)  # Each risk point deducts 10 from the grade
        grade = max(0, min(100, grade))  # Clamp grade between 0 and 100

        return {
            "link": link,
            "risk_category": risk_category,
            "threat_type": threat_type,
            "findings": findings,
            "domain": registered_domain,
            "user_feedback": user_feedback,
            "grade": grade
        }

detector = PhishingDetector()
detector = PhishingDetector()
print("PhishingDetector initialized")

# Dialogflow setup for chatbot
# Dialogflow setup
project_id     = "linkguardbot-njfk"
dialogflow_sid = "linkguard-session"
language_code  = "en"

# Dialogflow setup
project_id = "linkguardbot-njfk"
dialogflow_sid = "linkguard-session"
language_code = "en"

# Load Dialogflow credentials from environment variable
credentials_json = os.getenv("DIALOGFLOW_CREDENTIALS")
credentials_dict = json.loads(credentials_json)
credentials = service_account.Credentials.from_service_account_info(credentials_dict)
session_client = dialogflow.SessionsClient(credentials=credentials)
dialogflow_session = session_client.session_path(project_id, dialogflow_sid)
print("Dialogflow session initialized")

# Simulation URLs
simulation_urls = [
    {"url": "http://192.168.1.1/login", "is_phishing": True},
    {"url": "https://example.com", "is_phishing": False},
    {"url": "http://secure.login.bank.example.com/update", "is_phishing": True},
    {"url": "https://google.com", "is_phishing": False},
    {"url": "http://123.456.78.90/verify", "is_phishing": True}
]

def generate_threat_report(result):
    report = "Threat Report\n\n"
    report += f"URL: {result['link']}\n"
    report += "Reasons for High Risk:\n"
    for check, value in result["findings"].items():
        if value:
            if check == "Suspicious Path" and result["threat_type"]:
                report += f"- Suspicious Path: Detected {result['threat_type'].capitalize()} Pattern\n"
            else:
                report += f"- {check}\n"

    report += "\nPotential Risks:\n"
    if result["threat_type"] == "phishing":
        report += "- This URL is a phishing attempt designed to steal your credentials or personal information.\n"
        report += "- It may lead to financial loss, identity theft, or unauthorized access to your accounts.\n"
    elif result["threat_type"] == "malware":
        report += "- This URL may deliver malware that can harm your device or network.\n"
        report += "- It could install malicious software, steal data, or compromise your system’s security.\n"
    elif result["threat_type"] == "unwanted":
        report += "- This URL may attempt to install unwanted software on your device.\n"
        report += "- Such software can slow down your device, display unwanted ads, or track your activities.\n"
    elif result["threat_type"] == "billing":
        report += "- This URL may attempt to trick you into unauthorized billing or subscriptions.\n"
        report += "- It could lead to unexpected charges or financial loss.\n"
    else:
        report += "- This URL may attempt to steal your credentials or install malware.\n"
        report += "- It could lead to financial loss or identity theft.\n"

    report += "\nRecommended Actions:\n"
    report += "- Do not visit this link.\n"
    report += "- Report it to your IT team or email provider.\n"
    if result["threat_type"] == "malware" or result["threat_type"] == "unwanted":
        report += "- Scan your device for malware or unwanted software if you’ve already visited it.\n"
    else:
        report += "- Scan your device for malware if you’ve already visited it.\n"
    return report
dialogflow_session = session_client.session_path(project_id, dialogflow_sid)
print("Dialogflow session initialized")

# Login Required Decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# User Login Required Decorator
def user_login_required(f):
    def wrap(*args, **kwargs):
        if 'user_logged_in' not in session or not session['user_logged_in']:
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    stored_password = load_admin(username)

    if stored_password and stored_password == hashed_password:
        session['logged_in'] = True
        session['username'] = username
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Invalid username or password"}), 401

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/")
def index():
    print("Index route - Session contents:", dict(session))  # Debug
    # Restore session if username is passed as a query parameter
    username = request.args.get('username')
    if username and 'username' not in session:
        session['user_logged_in'] = True
        session['username'] = username
        session.permanent = True
        session.modified = True  # Ensure session is saved
        print("Restored session with username:", username)  # Debug
    print("Session after restore:", dict(session))  # Debug
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_url():
    print("Received scan request")  # Debug: Confirm the route is reached
    try:
        print("Parsing JSON data")  # Debug
        data = request.get_json()
        print(f"Received data: {data}")  # Debug
        url = data.get("url", "")
        source = data.get("source", "scan")  # Default to "scan" if not provided
        print(f"URL: {url}, Source: {source}")  # Debug
        if not url:
            print("No URL provided")  # Debug
            return jsonify({"error": "Please provide a URL"}), 400
        
        print("Evaluating link")  # Debug
        result = detector.evaluate_link(url)
        print(f"Evaluation result: {result}")  # Debug
        # Add threat report for High-risk URLs
        if result["risk_category"] == "High":
            print("Generating threat report")  # Debug
            result["threat_report"] = generate_threat_report(result)
        
        # Debug session state
        print("Session contents:", session)
        # Get the username from the session if the user is logged in
        username = session.get('username', None)
        print(f"Username from session: {username}")

        # Log to user-specific history if the user is logged in
        if username:
            print(f"Saving to user history for {username}")  # Debug
            save_user_scan_history(
                username=username,
                url=url,
                risk_category=result["risk_category"],
                threat_type=result["threat_type"],
                findings=result["findings"],
                threat_report=result.get("threat_report", ""),
                source=source
            )

        # Log to global history for admin
        print("Saving to global history")  # Debug
        save_scan_history(
            url=url,
            risk_category=result["risk_category"],
            threat_type=result["threat_type"],
            findings=result["findings"],
            threat_report=result.get("threat_report", ""),
            source=source,
            username=username
        )

        print("Returning scan result")  # Debug
        return jsonify(result)
    except Exception as e:
        print(f"Error scanning URL: {e}")  # Debug
        return jsonify({"error": f"Error scanning URL: {str(e)}"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "Please provide a message"}), 400

    try:
        text_input = dialogflow.TextInput(text=message, language_code=language_code)
        query_input = dialogflow.QueryInput(text=text_input)
        response = session_client.detect_intent(
            request={"session": dialogflow_session, "query_input": query_input}
        )
        return jsonify({"response": response.query_result.fulfillment_text})
    except Exception as e:
        return jsonify({"error": f"Error connecting to chatbot: {str(e)}"}), 500

@app.route("/simulation")
@user_login_required
def simulation():
    return render_template("simulation.html", urls=simulation_urls)

@app.route("/simulation/guess", methods=["POST"])
@user_login_required
def simulation_guess():
    data = request.get_json()
    url = data.get("url", "")
    user_guess = data.get("guess", False)  # true for phishing, false for safe

    print(f"Received guess: url={url}, guess={user_guess}")  # Debug print

    if not url:
        print("Error: No URL provided")  # Debug print
        return jsonify({"error": "No URL provided"}), 400

    # Find the URL in simulation_urls to determine if it's phishing
    # Since we're now using client-side links, we need to evaluate the URL directly
    result = detector.evaluate_link(url)
    is_phishing = result["risk_category"] == "High"  # Assume high risk means phishing

    correct = user_guess == is_phishing
    feedback = {
        "correct": correct,
        "message": f"{'Correct!' if correct else 'Incorrect.'} This URL {'is' if is_phishing else 'is not'} phishing.",
        "result": result
    }
    print(f"Returning feedback: {feedback}")  # Debug print

    # Add threat report for High-risk URLs
    if result["risk_category"] == "High":
        feedback["threat_report"] = generate_threat_report(result)

    # Get the username from the session (user must be logged in due to @user_login_required)
    username = session.get('username')

    # Log to user-specific history
    save_user_scan_history(
        username=username,
        url=url,
        risk_category=result["risk_category"],
        threat_type=result["threat_type"],
        findings=result["findings"],
        threat_report=feedback.get("threat_report", ""),
        source="simulation"
    )

    # Log to global history for admin
    save_scan_history(
        url=url,
        risk_category=result["risk_category"],
        threat_type=result["threat_type"],
        findings=result["findings"],
        threat_report=feedback.get("threat_report", ""),
        source="simulation",
        username=username  # Ensure username is passed
    )

    return jsonify(feedback)

print("About to start the Flask app...")
#admin 
@app.route("/admin")
@login_required
def admin():
    history = load_scan_history()
    # Filter out simulation scans
    history = [entry for entry in history if entry["source"] != "simulation"]
    print(f"Loaded history length (after filtering): {len(history)}")  # Debug log
    # Calculate risk distribution for pie chart
    risks = {"High": 0, "Medium": 0, "Low": 0}
    for entry in history:
        if isinstance(entry, dict) and "risk_category" in entry and entry["risk_category"] in risks:
            risks[entry["risk_category"]] += 1
        else:
            print(f"Invalid history entry: {entry}")  # Debug log for invalid entries
    # Load feedback data to pass to the template
    feedback = load_feedback()
    # Load all users
    users = load_all_users()
    total_entries = len(history)
    print(f"Total entries passed to template: {total_entries}")  # Debug log
    return render_template("admin.html", history=history, total_entries=total_entries, risks=risks, feedback=feedback, users=users)

@app.route("/admin/history", methods=["GET"])
@login_required
def get_full_history():
    history = load_scan_history()
    # Filter out simulation scans
    history = [entry for entry in history if entry["source"] != "simulation"]
    feedback = load_feedback()
    return jsonify({"history": history, "feedback": feedback})

@app.route("/admin/delete", methods=["POST"])
@login_required
def delete_history_entries():
    try:
        data = request.get_json()
        indices = data.get("indices", [])  # List of indices to delete
        if not indices:
            return jsonify({"error": "No indices provided"}), 400
        history = load_scan_history()
        # Sort indices in descending order to avoid index shifting when deleting
        indices.sort(reverse=True)
        for index in indices:
            if 0 <= index < len(history):
                # Save each deletion as a new entry to maintain history integrity
                entry = history.pop(index)
                save_scan_history(
                    url=entry["url"],
                    risk_category=entry["risk_category"],
                    threat_type=entry["threat_type"],
                    findings=entry["findings"],
                    threat_report=entry.get("threat_report", ""),
                    source="admin_delete",
                    username=None  # Admin actions don't have a username
                )
        # Save the remaining history
        save_scan_history(
            url="remaining_history",
            risk_category="N/A",
            threat_type=None,
            findings={},
            threat_report="",
            source="admin",
            username=None  # Admin actions don't have a username
        )
        if len(history) > 30:
            history = history[-30:]

        with open("scan_history.json", 'w') as f:
            json.dump(history, f, indent=2)
        return jsonify({"message": "Selected entries deleted successfully"})
    except Exception as e:
        print(f"Error deleting entries: {e}")  # Debug log
        return jsonify({"error": f"Error deleting entries: {str(e)}"}), 500

@app.route("/admin/clear", methods=["POST"])
@login_required
def clear_history():
    try:
        # Clear history by saving a single dummy entry or empty list indirectly
        save_scan_history(
            url="cleared",
            risk_category="N/A",
            threat_type=None,
            findings={},
            threat_report="",
            source="admin",
            username=None  # Admin actions don't have a username
        )
        # Overwrite with empty list to ensure clear
        with open("scan_history.json", 'w') as f:
            json.dump([], f, indent=2)
        print("Scan history cleared successfully")  # Debug log
        return jsonify({"message": "Scan history cleared successfully"})
    except Exception as e:
        print(f"Error clearing history: {e}")  # Debug log
        return jsonify({"error": f"Error clearing history: {str(e)}"}), 500

#deletion request from admin dashboard   
@app.route("/admin/delete_user", methods=["POST"])
@login_required
def delete_user_route():
    try:
        data = request.get_json()
        username = data.get("username", "")
        if not username:
            return jsonify({"error": "Username is required"}), 400
        
        delete_user(username)
        return jsonify({"message": f"User {username} deleted successfully"})
    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({"error": f"Error deleting user: {str(e)}"}), 500

@app.route("/export")
@login_required
def export():
    history = load_scan_history()
    # Generate CSV content with updated fields
    csv_content = "Timestamp,URL,Risk Level,Threat Type,IP Address,Risky Keywords,Subdomains,Length,Known Phishing Domain,Suspicious Path,Threat Report,Source\n"
    for entry in history:
        findings = entry["findings"]
        csv_content += (
            f"{entry['timestamp']},{entry['url']},{entry['risk_category']},{entry['threat_type'] or ''},"
            f"{'Yes' if findings['Uses IP Address'] else 'No'},"
            f"{'Yes' if findings['Risky Keywords'] else 'No'},"
            f"{'Yes' if findings['Too Many Subdomains'] else 'No'},"
            f"{'Yes' if findings['Excessive Length'] else 'No'},"
            f"{'Yes' if findings['Known Phishing Domain'] else 'No'},"
            f"{'Yes' if findings['Suspicious Path'] else 'No'},"
            f"{entry['threat_report'].replace(',', ';') if entry['threat_report'] else ''},"
            f"{entry['source']}\n"
        )
    # Create a temporary CSV file
    with open("scan_history_export.csv", "w") as f:
        f.write(csv_content)
    return send_file("scan_history_export.csv", as_attachment=True, download_name="scan_history.csv")

@app.route("/export_pdf")
@login_required
def export_pdf():
    history = load_scan_history()
    # Generate HTML content for PDF
    html_content = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid black; padding: 8px; text-align: left; }
            th { background-color: #4A90E2; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>LinkGuard Scanner - Scan History</h1>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>URL</th>
                <th>Risk Level</th>
                <th>Threat Type</th>
                <th>IP Address</th>
                <th>Risky Keywords</th>
                <th>Subdomains</th>
                <th>Length</th>
                <th>Known Phishing Domain</th>
                <th>Suspicious Path</th>
                <th>Threat Report</th>
                <th>Source</th>
            </tr>
    """
    for entry in history:
        findings = entry["findings"]
        # Handle the threat report replacement outside the f-string
        threat_report = entry['threat_report'].replace('\n', '<br>') if entry['threat_report'] else ''
        html_content += (
            f"<tr>"
            f"<td>{entry['timestamp']}</td>"
            f"<td>{entry['url']}</td>"
            f"<td>{entry['risk_category']}</td>"
            f"<td>{entry['threat_type'] or ''}</td>"
            f"<td>{'Yes' if findings['Uses IP Address'] else 'No'}</td>"
            f"<td>{'Yes' if findings['Risky Keywords'] else 'No'}</td>"
            f"<td>{'Yes' if findings['Too Many Subdomains'] else 'No'}</td>"
            f"<td>{'Yes' if findings['Excessive Length'] else 'No'}</td>"
            f"<td>{'Yes' if findings['Known Phishing Domain'] else 'No'}</td>"
            f"<td>{'Yes' if findings['Suspicious Path'] else 'No'}</td>"
            f"<td>{threat_report}</td>"
            f"<td>{entry['source']}</td>"
            f"</tr>"
        )
    html_content += """
        </table>
    </body>
    </html>
    """
    # Generate PDF
    pdf_file = "scan_history_export.pdf"
    pdfkit.from_string(html_content, pdf_file)
    return send_file(pdf_file, as_attachment=True, download_name="scan_history.pdf")

@app.route("/feedback", methods=["POST"])
def submit_feedback():
    data = request.get_json()
    url = data.get("url", "")
    user_assessment = data.get("user_assessment", "")  # "safe" or "unsafe"
    original_assessment = data.get("original_assessment", "")

    if not url or not user_assessment:
        return jsonify({"error": "URL and user assessment are required"}), 400

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    feedback_entry = {
        "timestamp": timestamp,
        "url": url,
        "user_assessment": user_assessment,
        "original_assessment": original_assessment
    }
    save_feedback(feedback_entry)

    # Update PhishingDetector with the feedback
    detector.load_feedback()

    return jsonify({"message": "Feedback submitted successfully"})

#Contact us
@app.route("/contact")
def contact():
    return render_template("contact.html")

#registering user
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if save_user(username, hashed_password):
        return jsonify({"success": True, "message": "Registration successful! Please log in."})
    else:
        return jsonify({"success": False, "message": "Username already exists"}), 409

# user login
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "GET":
        print("Serving user_login.html, Session before GET:", dict(session))  # Debug
        return render_template("user_login.html")

    print("Received login request, Session before POST:", dict(session))  # Debug
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    print(f"Login attempt for username: {username}")  # Debug

    if not username or not password:
        print("Missing username or password")  # Debug
        return jsonify({"success": False, "message": "Username and password are required"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    stored_password = load_user(username)
    print(f"Stored password: {stored_password}, Hashed password: {hashed_password}")  # Debug

    if stored_password and stored_password == hashed_password:
        session['user_logged_in'] = True
        session['username'] = username
        session.permanent = True  # Make session persistent
        print("Session after login:", dict(session))  # Debug
        # Force session to save by modifying it
        session.modified = True
        return jsonify({"success": True, "message": "Login successful! Redirecting to home page.", "redirect": url_for('index', username=username)})
    else:
        print("Invalid credentials")  # Debug
        return jsonify({"success": False, "message": "Invalid username or password"}), 401
    

#user logout
@app.route("/user_logout")
def user_logout():
    session.clear()  # Clear all session data
    return redirect(url_for('index'))

#user dashboard
@app.route("/user_dashboard")
@user_login_required
def user_dashboard():
    username = session.get('username')
    user_history = load_user_scan_history()
    
    # Get the user's specific history (already filtered by user in user_scan_history.json)
    history = user_history.get(username, [])
    
    # Filter out simulation scans to match admin dashboard behavior
    history = [entry for entry in history if entry["source"] != "simulation"]
    
    # Calculate risk distribution for pie chart
    risks = {"High": 0, "Medium": 0, "Low": 0}
    for entry in history:
        if isinstance(entry, dict) and "risk_category" in entry and entry["risk_category"] in risks:
            risks[entry["risk_category"]] += 1
    
    total_entries = len(history)
    return render_template("user_dashboard.html", history=history, total_entries=total_entries, risks=risks)
if __name__ == "__main__":
    try:
        print("About to start the Flask app...")
        import os
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port, debug=True)
    except Exception as e:
        print(f"Error starting Flask app: {e}")
        raise


