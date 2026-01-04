import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from datetime import datetime
from zoneinfo import ZoneInfo
import qrcode
import io
import base64

# ----------------- Flask App Setup -----------------
app = Flask(__name__)

app.config['SECRET_KEY'] = 'CHANGE_THIS_SECRET_KEY_123456789'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///traffic.db'
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
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20))  
    active = db.Column(db.Boolean, default=True)
    session_token = db.Column(db.String(100), nullable=True)

class Challan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challan_id = db.Column(db.String(50))
    offender = db.Column(db.String(100))
    vreg = db.Column(db.String(50))
    violation_code = db.Column(db.String(50))
    challan_amount = db.Column(db.Integer)
    received_by = db.Column(db.String(100))
    timestamp = db.Column(db.String(50))
    warden_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ----------------- Login Manager -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------- Force Logout System -----------------
@app.before_request
def check_force_logout():
    if current_user.is_authenticated and current_user.role == "warden":
        token = session.get("session_token")
        if token != current_user.session_token:
            logout_user()
            flash("You have been logged out by admin.")
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
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        user = User.query.filter_by(username=username, password=password).first()

        if user and user.active:
            login_user(user)

            # Generate session token
            token = os.urandom(16).hex()
            user.session_token = token
            session["session_token"] = token
            db.session.commit()

            return redirect(url_for("admin_dashboard" if user.role == "admin" else "warden_dashboard"))

        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ----------------- Admin Routes -----------------
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
        total_amount = sum(c.challan_amount + SERVICE_FEE for c in challans)

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

    name = request.form["name"]
    username = request.form["username"]
    password = request.form["password"]

    warden = User(name=name, username=username, password=password, role="warden")
    db.session.add(warden)
    db.session.commit()

    flash("Warden created successfully")
    return redirect(url_for("admin_dashboard"))


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

    flash(f"{warden.name} has been logged out.")
    return redirect(url_for("admin_dashboard"))


# ----------------- Warden Routes -----------------
@app.route("/warden/dashboard")
@login_required
def warden_dashboard():
    if current_user.role != "warden":
        flash("Unauthorized access")
        return redirect(url_for("login"))

    challans = Challan.query.filter_by(warden_id=current_user.id).all()
    total_amount = sum(c.challan_amount + SERVICE_FEE for c in challans)

    return render_template("warden_dashboard.html", challans=challans, total_amount=total_amount)


@app.route("/challan/create", methods=["GET", "POST"])
@login_required
def create_challan():
    if current_user.role != "warden":
        flash("Unauthorized")
        return redirect(url_for("login"))

    if request.method == "POST":
        challan_id = request.form["challan_id"]
        offender = request.form["offender"]
        vreg = request.form["vreg"]
        violation_code = request.form["violation_code"]
        challan_amount = int(request.form["challan_amount"])

        # ---------- Pakistan Standard Time ----------
        timestamp = datetime.now(ZoneInfo("Asia/Karachi")).strftime("%m/%d/%Y %I:%M:%S %p")

        challan = Challan(
            challan_id=challan_id,
            offender=offender,
            vreg=vreg,
            violation_code=violation_code,
            challan_amount=challan_amount,
            received_by=current_user.name,
            timestamp=timestamp,
            warden_id=current_user.id,
        )

        db.session.add(challan)
        db.session.commit()

        return redirect(url_for("view_challan", challan_id=challan.id))

    return render_template("challan_form.html")



@app.route("/challan/<int:challan_id>")
@login_required
def view_challan(challan_id):
    challan = Challan.query.get_or_404(challan_id)
    total_amount = challan.challan_amount + SERVICE_FEE
     
    # --- Updated QR Format ---
    qr_data = f"AEA10A8D{challan.challan_id}|{total_amount}"
    qr_code = generate_qr(qr_data)

    return render_template("challan.html",
                           challan=challan,
                           total_amount=total_amount,
                           service_fee=SERVICE_FEE,
                           qr_code=qr_code)


# ----------------- Admin View All Challans -----------------
@app.route("/admin/challans")
@login_required
def view_all_challans():
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))

    challans = Challan.query.order_by(Challan.timestamp.desc()).all()
    return render_template("admin_challans.html",
                           challans=challans,
                           service_fee=SERVICE_FEE)


@app.route("/admin/challan/<int:challan_id>/delete", methods=["POST"])
@login_required
def delete_challan(challan_id):
    if current_user.role != "admin":
        flash("Unauthorized")
        return redirect(url_for("login"))

    challan = Challan.query.get_or_404(challan_id)
    db.session.delete(challan)
    db.session.commit()

    flash(f"Challan {challan.challan_id} deleted successfully.")
    return redirect(url_for("view_all_challans"))


@app.route("/admin/register", methods=["GET", "POST"])
@login_required
def register_user():
    if current_user.role != "admin":
        flash("Unauthorized access")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # admin or warden

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("register_user"))

        new_user = User(name=name, username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash(f"{role.capitalize()} registered successfully")
        return redirect(url_for("admin_dashboard"))

    return render_template("register_user.html")


# ----------------- Run App -----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Create default admin if not exists
        if not User.query.filter_by(username="admin").first():
            admin = User(
                name="Admin",
                username="admin",
                password="admin",
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: username=admin, password=admin")

    app.run(debug=False, host="0.0.0.0")





