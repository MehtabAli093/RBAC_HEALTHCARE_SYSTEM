# Healthcare System

A Flask-powered, MongoDB-driven, role-based, OTP-secured web application for managing medical records, appointments, and user roles in a healthcare setting.

## Overview

The Healthcare System is a secure and efficient web application designed to streamline healthcare operations. Built with Flask, MongoDB, and Python, it incorporates robust security features like two-factor authentication (OTP), role-based access control (RBAC), and encrypted data storage. The system supports multiple user roles (admins, doctors, nurses, patients) and provides functionalities such as appointment scheduling, medical record management, and activity logging.

This project was developed as part of a cybersecurity academic endeavor at the National University of Computer & Emerging Sciences by Mehtab Ahmed (22K-4771).

## Features

- **Role-Based Access Control (RBAC)**: Restricts access based on user roles (admin, doctor, nurse, patient) to ensure data privacy.
- **Two-Factor Authentication (OTP)**: Enhances security by requiring a 6-digit OTP sent via email during login.
- **Encrypted Data Storage**: Uses Fernet encryption to secure medical records and nursing notes.
- **Appointment Management**: Allows patients to book appointments, doctors to approve/reject them, and nurses to be assigned.
- **Activity Logging**: Tracks user actions for auditing and security monitoring.
- **User-Friendly Dashboards**: Role-specific dashboards for admins (user management), doctors (record/appointment management), nurses (note addition), and patients (record viewing, appointment booking).

## Technologies Used

- **Backend**: Flask, Python, PyMongo
- **Database**: MongoDB
- **Security**: Fernet (Cryptography library), Flask-Bcrypt, Flask-Login
- **Frontend**: HTML, CSS, Jinja2 templates
- **Email Service**: SMTP (e.g., Gmail for OTP notifications)
- **Development Environment**: Python 3.8+, MongoDB Community Edition

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.8 or higher
- MongoDB Community Edition
- A web browser (e.g., Chrome, Firefox)
- An SMTP server (e.g., Gmail) for OTP email notifications

Hardware requirements:
- PC with 4GB RAM, 2GHz processor, and 256GB storage

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MehtabAli093/RBAC_HEALTHCARE_SYSTEM.git
   cd RBAC_HEALTHCARE_SYSTEM
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Example `requirements.txt`:
   ```
   flask==2.0.1
   pymongo==4.3.3
   flask-bcrypt==1.0.1
   flask-login==0.6.2
   cryptography==41.0.3
   ```

4. **Configure MongoDB**:
   - Install and start MongoDB locally or use a cloud instance (e.g., MongoDB Atlas).
   - Update the MongoDB connection string in the application configuration (e.g., in `RBAC.py` or environment variables).

5. **Set Up SMTP for OTP**:
   - Configure an SMTP server (e.g., Gmail) by setting environment variables:
     ```bash
     export EMAIL_USER='your-email@gmail.com'
     export EMAIL_PASS='your-app-password'
     ```
   - Replace `your-app-password` with a Gmail App Password if using Gmail.

6. **Run the Application**:
   ```bash
   python RBAC.py
   ```
   - Access the application at `http://localhost:5000` in your browser.

## Usage

1. **Register Users**:
   - Navigate to the registration page to create accounts for admins, doctors, nurses, or patients.
   - Each user is assigned a role during registration.

2. **Login with OTP**:
   - Log in with your credentials.
   - Enter the 6-digit OTP sent to your registered email to access your role-specific dashboard.

3. **Role-Specific Actions**:
   - **Admins**: Manage users and view activity logs.
   - **Doctors**: Manage medical records and approve/reject appointments.
   - **Nurses**: Add nursing notes and view assigned appointments.
   - **Patients**: View medical records and book appointments.

4. **Database Management**:
   - MongoDB stores user data, medical records, appointments, and logs.
   - Use a MongoDB client (e.g., MongoDB Compass) to view the database.



## Contact

For questions or support, contact:
mehtabahmed093@gmail.com
*Developed for the Department of Cyber Security, National University of Computer & Emerging Sciences, May 2025.*
