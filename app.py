# app.py
import os
import io
import base64
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

# Optional pdfkit import (only used if wkhtmltopdf path is provided)
try:
    import pdfkit
except Exception:
    pdfkit = None

# ----------------- Config -----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
# Use DATABASE_URL env var if present (for future migration), otherwise use local sqlite file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///traffic.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

SERVICE_FEE = 17

# ----------------- Models -----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # hashed
    role = db.Column(db.String(20))  # admin or warden
    active = db.Column(db.Boolean, default=True)
    session_token = db.Column(db.String(100), nullable=True)

    def set_password(self, raw):
        self.password = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password, raw)

class Challan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challan_id = db.Column(db.String(50), unique=True)
    offender = db.Column(db.String(100))
    vreg = db.Column(db.String(50))
    violation_code = db.Column(db.String(50))
    challan_amount = db.Column(db.Integer)
    received_by = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    warden_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    warden = db.relationship('User', backref='challans')

# ----------------- Login Manager -----------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

# Avoid redirect loop: only check for force-logout on endpoints that require login and not static/login endpoints
@app.before_request
def check_force_logout():
    # skip when not authenticated or when hitting login/logout/static endpoints
    if not current_user.is_authenticated:
        return
    if current_user.role != "warden":
        return
    # if user has been force-logged out by admin (session token mismatch), log them out
    token = session.get("session_token")
    if token and current_user.session_token and token != current_user.session_token:
        logout_user()
        flash("You have been logged out by admin")
        return redirect(url_for("login"))

# ----------------- QR Code -----------------
def generate_qr(data):
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

# ----------------- Routes -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.active and user.check_password(password):
            login_user(user)
            token = os.urandom(16).hex()
            user.session_token = token
            session['session_token'] = token
            db.session.commit()
            if user.role == "admin":
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('warden_dashboard'))
        flash("Invalid credentials or inactive user")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ----------------- Admin -----------------
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))
    wardens = User.query.filter_by(role="warden").all()
    warden_stats = []
    for w in wardens:
        challans = Challan.query.filter_by(warden_id=w.id).all()
        total_amount = sum((c.challan_amount or 0) + SERVICE_FEE for c in challans)
        warden_stats.append({
            "warden": w,
            "challans_created": len(challans),
            "total_amount": total_amount
        })
    return render_template("admin_dashboard.html", warden_stats=warden_stats)

@app.route("/admin/warden/create", methods=["POST"])
@login_required
def create_warden():
    if current_user.role != "admin":
        flash("Unauthorized")
        return redirect(url_for("login"))
    name = request.form.get('name', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        flash("Username and password required")
        return redirect(url_for('admin_dashboard'))
    if User.query.filter_by(username=username).first():
        flash("Username already exists")
        return redirect(url_for('admin_dashboard'))
    warden = User(name=name, username=username, role="warden")
    warden.set_password(password)
    db.session.add(warden)
    db.session.commit()
    flash("Warden created successfully")
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/warden/toggle/<int:warden_id>")
@login_required
def toggle_warden(warden_id):
    if current_user.role != "admin":
        flash("Unauthorized")
        return redirect(url_for("login"))
    warden = User.query.get_or_404(warden_id)
    warden.active = not warden.active
    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/warden/force_logout/<int:warden_id>")
@login_required
def force_logout_warden(warden_id):
    if current_user.role != "admin":
        flash("Unauthorized")
        return redirect(url_for("login"))
    warden = User.query.get_or_404(warden_id)
    warden.session_token = None
    db.session.commit()
    flash(f"{warden.name} has been logged out")
    return redirect(url_for("admin_dashboard"))

# ----------------- Warden -----------------
@app.route("/warden/dashboard")
@login_required
def warden_dashboard():
    if current_user.role != "warden":
        flash("Unauthorized access")
        return redirect(url_for("login"))
    challans = Challan.query.filter_by(warden_id=current_user.id).all()
    total_amount = sum((c.challan_amount or 0) + SERVICE_FEE for c in challans)
    return render_template("warden_dashboard.html", challans=challans, total_amount=total_amount)

@app.route("/challan/create", methods=["GET", "POST"])
@login_required
def create_challan():
    if current_user.role != "warden":
        flash("Unauthorized")
        return redirect(url_for("login"))
    if request.method == "POST":
        challan_id = request.form.get('challan_id', '').strip()
        offender = request.form.get('offender', '').strip()
        vreg = request.form.get('vreg', '').strip()
        violation_code = request.form.get('violation_code', '').strip()
        try:
            challan_amount = int(request.form.get('challan_amount', 0))
        except ValueError:
            challan_amount = 0
        timestamp = datetime.utcnow()
        received_by = current_user.name
        warden_id = current_user.id
        challan = Challan(challan_id=challan_id, offender=offender, vreg=vreg,
                          violation_code=violation_code, challan_amount=challan_amount,
                          received_by=received_by, timestamp=timestamp, warden_id=warden_id)
        db.session.add(challan)
        db.session.commit()
        return redirect(url_for('view_challan', challan_id=challan.id))
    return render_template("challan_form.html")

@app.route("/challan/<int:challan_id>")
@login_required
def view_challan(challan_id):
    challan = Challan.query.get_or_404(challan_id)
    total_amount = (challan.challan_amount or 0) + SERVICE_FEE
    qr_code = generate_qr(challan.challan_id or "")
    return render_template("challan.html", challan=challan, total_amount=total_amount, service_fee=SERVICE_FEE, qr_code=qr_code)

@app.route("/challan/<int:challan_id>/pdf")
@login_required
def download_pdf(challan_id):
    challan = Challan.query.get_or_404(challan_id)
    total_amount = (challan.challan_amount or 0) + SERVICE_FEE
    qr_code = generate_qr(challan.challan_id or "")
    html = render_template("challan_pdf.html", challan=challan, total_amount=total_amount,
                           service_fee=SERVICE_FEE, qr_code=qr_code)

    wk_cmd = os.environ.get('WKHTMLTOPDF_CMD')  # e.g. '/usr/bin/wkhtmltopdf' if available
    if pdfkit and wk_cmd:
        config = pdfkit.configuration(wkhtmltopdf=wk_cmd)
        pdf_bytes = pdfkit.from_string(html, False, configuration=config)
        return (pdf_bytes, 200, {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'attachment; filename="challan_{challan.challan_id or challan.id}.pdf"'
        })
    # fallback: if pdf not configured, return HTML page so user can "Print -> Save as PDF" from browser
    flash("PDF generation not configured on server. Use browser Print -> Save as PDF or configure WKHTMLTOPDF_CMD.")
    return render_template("challan_pdf.html", challan=challan, total_amount=total_amount,
                           service_fee=SERVICE_FEE, qr_code=qr_code)

@app.route("/admin/register", methods=["GET", "POST"])
@login_required
def register_user():
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get('name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'warden')

        if not username or not password:
            flash("Username and password required")
            return redirect(url_for("register_user"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("register_user"))

        new_user = User(name=name, username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash(f"{role.capitalize()} registered successfully")
        return redirect(url_for("admin_dashboard"))

    return render_template("register_user.html")

# Admin: View All Challans
@app.route("/admin/challans")
@login_required
def view_all_challans():
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))
    challans = Challan.query.order_by(Challan.timestamp.desc()).all()
    return render_template("admin_challans.html", challans=challans, service_fee=SERVICE_FEE)

# Admin: Delete Challan
@app.route("/admin/challan/<int:challan_id>/delete", methods=["POST"])
@login_required
def delete_challan(challan_id):
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))
    challan = Challan.query.get_or_404(challan_id)
    db.session.delete(challan)
    db.session.commit()
    flash(f"Challan {challan.challan_id} deleted successfully.")
    return redirect(url_for("view_all_challans"))

# ----------------- Initialization -----------------
# Create DB and a default admin if missing (safe to run on import)
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(name="Admin", username="admin", role="admin")
        admin.set_password("admin")  # change this later
        db.session.add(admin)
        db.session.commit()

# Note: On PythonAnywhere, the WSGI file will import `app` and run it via gunicorn/uWSGI.
# Do NOT call app.run() here.
