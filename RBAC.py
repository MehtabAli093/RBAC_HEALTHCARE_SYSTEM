# 1. Imports
import os
from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from functools import wraps
from cryptography.fernet import Fernet
import logging
import random
import smtplib
from bson import ObjectId
import datetime
from email.mime.text import MIMEText

# 2. Application Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["MONGO_URI"] = "yourmongodburihere"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 3. Logging Setup
logging.basicConfig(filename='access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# 4. Encryption Key Management
KEY_FILE = "encryption_key.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        encryption_key = key_file.read()
else:
    encryption_key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(encryption_key)
cipher = Fernet(encryption_key)

# 5. Email Configuration
EMAIL_ADDRESS = "sender`s email"
EMAIL_PASSWORD = "sender`s email password"

# 6. Role-Based Permissions
roles_permissions = {
    "admin": ["view_all", "edit_all"],
    "doctor": ["view_patient", "edit_patient"],
    "nurse": ["view_patient", "add_notes","view_nursing_notes"],
    "patient": ["view_self", "view_nursing_notes"]
}

# 7. User Model
class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.role = user_doc['role']

@login_manager.user_loader
def load_user(user_id):
    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None

# 8. Utility Functions
def role_required(required_permissions):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_user.is_authenticated:
                user_role = current_user.role
                permissions = roles_permissions.get(user_role, [])
                if any(rp in permissions for rp in required_permissions):
                    return f(*args, **kwargs)
                return render_template("unauthorized.html")
            return redirect(url_for('login'))
        return wrapper
    return decorator

def send_otp(email, otp):
    subject = "Your OTP for Login"
    body = f"Your OTP code is: {otp}\n\nDo not share this with anyone."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        flash(f"OTP sent to {email}.", "otp_success")
        return redirect(url_for('verify_otp'))
    except Exception as e:
        print("❌ Failed to send OTP:", e)
        flash("Failed to send OTP. Please check email settings.", "otp_error")

def log_access(username, role, action):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] User: {username} | Role: {role} | Action: {action}"
    with open("user_activity.log", "a") as log_file:
        log_file.write(log_message + "\n")

def send_role_change_email(email, old_role, new_role, changed_by):
    subject = "🔐 Your Role Has Been Updated"
    body = f"""
    Hello,

    Your role in the Healthcare System has been changed from '{old_role}' to '{new_role}' by '{changed_by}'.

    If you were expecting this, no action is required.
    If not, please contact the system administrator immediately.

    Regards,
    Healthcare Admin System
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        print(f"📧 Role change email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send role change email: {e}")

# 9. Authentication Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        email = data['email']
        password = data['password']
        role = data['role']

        if mongo.db.users.find_one({"email": email}):
            flash("This email is already registered. Please use another.", "danger")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw,
            'role': role
        })

        log_access(username, role, "Registered new account")
        flash("User registered successfully", "success")
        return redirect(url_for('login'))


    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user_doc = mongo.db.users.find_one({'username': data['username']})

        if user_doc and bcrypt.check_password_hash(user_doc['password'], data['password']):
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['user_id'] = str(user_doc['_id'])
            send_otp(user_doc['email'], otp)
            flash(f"OTP sent to {user_doc['email']}.", "otp")
            return redirect(url_for('verify_otp'))

        flash("Invalid credentials", "login_error")

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form.get('otp')
        if 'user_id' not in session:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for('login'))
        user_doc = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user_doc:
            flash("User not found. Please register or log in again.", "danger")
            return redirect(url_for('login'))
        if input_otp == session.get('otp'):
            user = User(user_doc)
            login_user(user)
            session.pop('otp')
            log_access(user.username, user.role, "Signed in")
            return redirect(url_for('dashboard'))
        flash("Invalid OTP. Please try again.", "otp_error")
    return render_template('verify_otp.html')

@app.route('/logout')
@login_required
def logout():
    log_access(current_user.username, current_user.role, "Logged out")
    logout_user()
    return redirect(url_for('login'))

# 10. Dashboard Routes
@app.route('/dashboard')
@login_required
def dashboard():
    log_access(current_user.username, current_user.role, "Viewed Dashboard")
    return render_template('dashboard.html', role=current_user.role)

@app.route('/nurse_dashboard')
@login_required
@role_required(['view_patient'])
def nurse_dashboard():
    log_access(current_user.username, current_user.role, "Accessed Nurse Dashboard")
    return render_template('nurse_dashboard.html', role=current_user.role)

# 11. Appointment Routes
@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
@role_required(['view_self'])
def book_appointment():
    if request.method == 'POST':
        doctor_username = request.form.get('doctor')
        date = request.form.get('date')
        time = request.form.get('time')

        if not doctor_username or not date or not time:
            flash("All fields are required!", "danger")
            return redirect(url_for('book_appointment'))

        mongo.db.appointments.insert_one({
            "patient": current_user.username,
            "doctor": doctor_username,
            "date": date,
            "time": time,
            "status": "pending"
        })

        log_access(current_user.username, current_user.role, f"Requested appointment with {doctor_username}")
        flash("Appointment request sent!", "success")
        return redirect(url_for('dashboard'))

    doctors = mongo.db.users.find({"role": "doctor"}, {"username": 1})
    return render_template("book_appointment.html", doctors=doctors)

@app.route('/appointments')
@login_required
@role_required(['view_patient'])
def view_appointments():
    appointments = mongo.db.appointments.find({'doctor': current_user.username})
    return render_template("appointments.html", appointments=appointments)

@app.route('/approve_appointment/<appointment_id>', methods=['POST'])
@login_required
@role_required(['view_patient'])
def approve_appointment(appointment_id):
    mongo.db.appointments.update_one({"_id": ObjectId(appointment_id)}, {"$set": {"status": "approved"}})
    log_access(current_user.username, current_user.role, f"Approved appointment {appointment_id}")
    flash("Appointment approved!", "success")
    return redirect(url_for('view_appointments'))

@app.route('/reject_appointment/<appointment_id>', methods=['POST'])
@login_required
@role_required(['view_patient'])
def reject_appointment(appointment_id):
    mongo.db.appointments.update_one({"_id": ObjectId(appointment_id)}, {"$set": {"status": "rejected"}})
    log_access(current_user.username, current_user.role, f"Rejected appointment {appointment_id}")
    flash("Appointment rejected!", "danger")
    return redirect(url_for('view_appointments'))

@app.route('/my_appointments')
@login_required
@role_required(['view_self'])
def my_appointments():
    appointments = mongo.db.appointments.find({'patient': current_user.username})
    return render_template("my_appointments.html", appointments=appointments)

@app.route('/nurse_appointments')
@login_required
@role_required(['view_patient'])
def nurse_appointments():
    appointments = mongo.db.appointments.find({})
    log_access(current_user.username, current_user.role, "Viewed Appointments")
    return render_template("nurse_appointments.html", appointments=appointments)

@app.route('/assign_nurse', methods=['GET', 'POST'])
@login_required
@role_required(['edit_patient'])
def assign_nurse():
    if request.method == 'POST':
        patient = request.form.get('patient')
        nurse = request.form.get('nurse')

        if not patient or not nurse:
            flash("Please select both a patient and a nurse!", "danger")
            return redirect(url_for('assign_nurse'))

        mongo.db.appointments.update_one(
            {"patient": patient, "doctor": current_user.username},
            {"$set": {"nurse_assigned": nurse}}
        )

        flash(f"Nurse {nurse} assigned to {patient} successfully!", "success")
        return redirect(url_for('dashboard'))

    approved_patients = mongo.db.appointments.find({"doctor": current_user.username, "status": "approved"})
    nurses = mongo.db.users.find({"role": "nurse"}, {"username": 1})
    return render_template('assign_nurse.html', patients=approved_patients, nurses=nurses)

# 12. Medical Record Routes
@app.route('/add_record', methods=['GET', 'POST'])
@login_required
@role_required(['edit_patient'])
def add_record():
    if current_user.role != 'doctor':
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    patients = mongo.db.appointments.find({"doctor": current_user.username, "status": "approved"})
    patient_list = [p["patient"] for p in patients]

    if request.method == 'POST':
        selected_patient = request.form.get('patient')
        record_data = request.form.get('record')

        if not selected_patient or not record_data:
            flash("Both Patient Name and Record Data are required!", "danger")
            return redirect(url_for('add_record'))

        if selected_patient not in patient_list:
            flash("Invalid Patient Selection!", "danger")
            return redirect(url_for('add_record'))

        encrypted_data = cipher.encrypt(record_data.encode())
        print("Inserting record:", {
            'owner': selected_patient,
            'patient_name': selected_patient,
            'data': encrypted_data,
            'assigned_doctor': current_user.username,
            'created_at': datetime.datetime.now()
        })

        mongo.db.records.insert_one({
            'owner': selected_patient,
            'patient_name': selected_patient,
            'data': encrypted_data,
            'assigned_doctor': current_user.username,
            'created_at': datetime.datetime.now()
        })

        flash("Record added successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_record.html', patients=patient_list)

@app.route('/view_records')
@login_required
@role_required(['view_patient', 'view_self'])
def view_records():
    if current_user.role == "doctor":
        records = mongo.db.records.find({'assigned_doctor': current_user.username})
        template_name = "doc_records.html"
    elif current_user.role == "nurse":
        records = mongo.db.records.find({})
        template_name = "nurse_records.html"
    elif current_user.role == "patient":
        records = mongo.db.records.find({'owner': current_user.username})
        template_name = "patient_records.html"
    else:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    decrypted_records = []
    for r in records:
        try:
            decrypted_text = cipher.decrypt(r["data"]).decode()
        except Exception:
            decrypted_text = "[ERROR: Unreadable Record]"

        decrypted_records.append({
            "_id": str(r["_id"]),
            "patient": r.get("patient_name", "Unknown"),
            "data": decrypted_text,
            "assigned_doctor": r.get("assigned_doctor", "Not Assigned"),
            "created_at": r.get("created_at", None)
        })

    if current_user.role == "patient" and not decrypted_records:
        flash("No medical records found.", "info")

    log_access(current_user.username, current_user.role, "Viewed Records")
    return render_template(template_name, records=decrypted_records)

@app.route('/delete_records', methods=['POST'])
@login_required
@role_required(['edit_patient'])
def delete_records():
    selected_records = request.form.getlist('record_ids')

    if not selected_records:
        flash("No records selected for deletion.", "warning")
        return redirect(url_for('view_records'))

    try:
        print("🚀 Selected Record IDs:", selected_records)
        for record_id in selected_records:
            if record_id.strip():
                print(f"🗑️ Deleting record: {record_id}")
                mongo.db.records.delete_one({"_id": ObjectId(record_id)})
        flash(f"Deleted {len(selected_records)} record(s) successfully!", "success")
        log_access(current_user.username, current_user.role, f"Deleted {len(selected_records)} records")
    except Exception as e:
        flash(f"Error deleting records: {str(e)}", "danger")

    return redirect(url_for('view_records'))

@app.route('/nurse_records')
@login_required
@role_required(['view_patient'])
def nurse_records():
    assigned_patients = mongo.db.appointments.find({"nurse_assigned": current_user.username})
    patient_list = [p["patient"] for p in assigned_patients]
    records = mongo.db.records.find({"owner": {"$in": patient_list}})

    decrypted_records = []
    for r in records:
        try:
            decrypted_text = cipher.decrypt(r["data"]).decode()
        except Exception:
            decrypted_text = "[ERROR: Unable to decrypt record]"

        decrypted_records.append({
            "patient": r["owner"],
            "data": decrypted_text,
            "assigned_doctor": r.get("assigned_doctor", "Not Assigned")
        })

    return render_template("nurse_records.html", records=decrypted_records)

# 13. Nursing Notes Routes
@app.route('/add_nursing_note', methods=['GET', 'POST'])
@login_required
@role_required(['add_notes'])
def add_nursing_note():
    if request.method == 'POST':
        patient = request.form.get('patient')
        note = request.form.get('note')

        if not patient or not note:
            flash("Patient name and note are required!", "danger")
            return redirect(url_for('add_nursing_note'))

        encrypted_note = cipher.encrypt(note.encode())
        mongo.db.nursing_notes.insert_one({
            "nurse": current_user.username,
            "patient": patient,
            "note": encrypted_note,
            "timestamp": datetime.datetime.now()
        })

        flash("Nursing note added successfully!", "success")
        return redirect(url_for('dashboard'))

    assigned_patients = mongo.db.appointments.find({
        "nurse_assigned": current_user.username,
        "status": "approved"
    })
    patient_list = list(set([p["patient"] for p in assigned_patients]))
    return render_template("add_nursing_note.html", patients=patient_list)

@app.route('/view_nursing_notes')
@login_required
@role_required(['view_nursing_notes'])
def view_nursing_notes():
    if current_user.role == 'patient':
        notes = mongo.db.nursing_notes.find({"patient": current_user.username})
    elif current_user.role == 'nurse':
        assigned_patients = mongo.db.appointments.find({"nurse_assigned": current_user.username})
        patient_list = [p["patient"] for p in assigned_patients]
        notes = mongo.db.nursing_notes.find({"patient": {"$in": patient_list}})
    else:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard'))

    decrypted_notes = []
    for note in notes:
        try:
            decrypted_text = cipher.decrypt(note["note"]).decode()
        except Exception:
            decrypted_text = "[ERROR: Unreadable Note]"

        decrypted_notes.append({
            "nurse": note["nurse"],
            "patient": note["patient"],
            "note": decrypted_text,
            "timestamp": note["timestamp"]
        })

    return render_template("nurse_notes.html", notes=decrypted_notes)

# 14. Admin Routes
@app.route('/manage_users')
@login_required
@role_required(['view_all'])
def manage_users():
    users = list(mongo.db.users.find({}, {"_id": 1, "username": 1, "email": 1, "role": 1}))
    log_access(current_user.username, current_user.role, "Accessed Manage Users")
    return render_template('manage_users.html', users=users)

@app.route('/update_user_role/<user_id>', methods=['POST'])
@login_required
@role_required(['view_all'])
def update_user_role(user_id):
    new_role = request.form.get('role')
    user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if not user_doc:
        flash("User not found!", "danger")
        return redirect(url_for('manage_users'))

    old_role = user_doc["role"]
    username = user_doc["username"]
    email = user_doc["email"]

    mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})

    if old_role == "doctor":
        mongo.db.records.delete_many({"assigned_doctor": username})
        doctor_appointments = list(mongo.db.appointments.find({"doctor": username}))
        for appointment in doctor_appointments:
            patient = appointment["patient"]
            mongo.db.appointments.update_many(
                {"patient": patient, "doctor": username},
                {"$unset": {"nurse_assigned": ""}}
            )
            mongo.db.nursing_notes.delete_many({
                "patient": patient,
                "nurse": {"$in": [appointment.get("nurse_assigned", "")]}
            })
        mongo.db.appointments.delete_many({"doctor": username})

    elif old_role == "nurse":
        mongo.db.nursing_notes.delete_many({"nurse": username})
        mongo.db.appointments.update_many(
            {"nurse_assigned": username},
            {"$unset": {"nurse_assigned": ""}}
        )

    elif old_role == "patient":
        mongo.db.records.delete_many({"owner": username})
        mongo.db.nursing_notes.delete_many({"patient": username})
        mongo.db.appointments.delete_many({"patient": username})

    send_role_change_email(email, old_role, new_role, changed_by=current_user.username)
    log_access(current_user.username, current_user.role, f"Changed role of '{username}' from {old_role} to {new_role}")
    flash(f"{username}'s role updated from {old_role} to {new_role}. All related data cleaned.", "success")
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@role_required(['view_all'])
def delete_user(user_id):
    user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if not user_doc:
        flash("User not found!", "danger")
        return redirect(url_for('manage_users'))

    username = user_doc["username"]
    role = user_doc["role"]
    email = user_doc["email"]

    if role == "doctor":
        mongo.db.records.delete_many({"assigned_doctor": username})
        doctor_appointments = list(mongo.db.appointments.find({"doctor": username}))
        for appointment in doctor_appointments:
            patient = appointment["patient"]
            assigned_nurse = appointment.get("nurse_assigned", None)
            if assigned_nurse:
                mongo.db.nursing_notes.delete_many({
                    "patient": patient,
                    "nurse": assigned_nurse
                })
        mongo.db.appointments.delete_many({"doctor": username})

    elif role == "nurse":
        mongo.db.nursing_notes.delete_many({"nurse": username})
        mongo.db.appointments.update_many(
            {"nurse_assigned": username},
            {"$unset": {"nurse_assigned": ""}}
        )

    elif role == "patient":
        mongo.db.records.delete_many({"owner": username})
        mongo.db.nursing_notes.delete_many({"patient": username})
        mongo.db.appointments.delete_many({"patient": username})

    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    log_access(current_user.username, current_user.role, f"Deleted {role} user: {username}")
    flash(f"{username} ({role}) and all related data deleted successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/view_logs')
@login_required
@role_required(['view_all'])
def view_logs():
    log_file_path = "user_activity.log"
    if not os.path.exists(log_file_path):
        logs = ["No user activity logs found."]
    else:
        with open(log_file_path, "r") as log_file:
            logs = log_file.readlines()[-20:]
    log_access(current_user.username, current_user.role, "Viewed Access Logs")
    return render_template("view_logs.html", logs=logs)

#15. Error Routes
@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

# 16. Main Application Runner
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)