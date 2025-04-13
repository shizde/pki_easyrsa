import os
import subprocess
import logging
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
    send_file,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReverseProxied(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["wsgi.url_scheme"] = "https"

        # Get the X-Forwarded-Host header which includes the port
        if "HTTP_X_FORWARDED_HOST" in environ:
            environ["HTTP_HOST"] = environ["HTTP_X_FORWARDED_HOST"]
        elif "HTTP_X_FORWARDED_PORT" in environ:
            host = environ.get("HTTP_HOST", "")
            # If host doesn't have a port, add the forwarded port
            if ":" not in host:
                port = environ["HTTP_X_FORWARDED_PORT"]
                environ["HTTP_HOST"] = f"{host}:{port}"

        return self.app(environ, start_response)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@{os.environ.get('DB_HOST')}/{os.environ.get('DB_NAME')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CA_PATH"] = os.environ.get("CA_PATH", "/ca")
app.config["UPLOAD_FOLDER"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "uploads"
)
app.config["PREFERRED_URL_SCHEME"] = "https"
app.config["APPLICATION_ROOT"] = "/"
app.wsgi_app = ReverseProxied(app.wsgi_app)

# Ensure upload directory exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)
    has_certificate = db.Column(db.Boolean, default=False)
    certificates = db.relationship("Certificate", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    issued_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    revocation_date = db.Column(db.DateTime, nullable=True)
    certificate_type = db.Column(db.String(20), nullable=False)  # 'user' or 'service'
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables if they don't exist
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", email="admin@company.com")
        admin.set_password("admin")  # Change this in production
        db.session.add(admin)
        db.session.commit()
        logger.info("Admin user created")


def run_ca_command(cmd_args, working_dir=None):
    """Run a command in the CA container and return the result"""
    if working_dir is None:
        working_dir = app.config["CA_PATH"]

    try:
        full_cmd = ["bash", "-c", " ".join(cmd_args)]
        logger.info(f"Running command: {' '.join(full_cmd)}")

        result = subprocess.run(
            full_cmd,
            cwd=working_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        return False, e.stderr


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    # Note: For certificate auth, the actual authentication is handled by the reverse proxy
    # This is just for password login or showing the login page
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_certs = Certificate.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", certificates=user_certs)


@app.route("/certificates")
@login_required
def certificates():
    # For admins, show all certificates, for regular users, show only their own
    if current_user.username == "admin":
        all_certs = Certificate.query.all()
    else:
        all_certs = Certificate.query.filter_by(user_id=current_user.id).all()

    return render_template("certificates.html", certificates=all_certs)


@app.route("/generate_certificate", methods=["GET", "POST"])
@login_required
def generate_certificate():
    if request.method == "POST":
        cert_type = request.form.get("cert_type")
        common_name = request.form.get("common_name")

        # Generate certificate request
        success, output = run_ca_command(
            [
                f"cd /ca && ./easyrsa --batch --req-cn='{common_name}' gen-req {common_name} nopass"
            ]
        )

        if not success:
            flash(f"Failed to generate certificate request: {output}")
            return redirect(url_for("generate_certificate"))

        # Sign the certificate based on type
        cert_type_arg = "client" if cert_type == "user" else "server"
        success, output = run_ca_command(
            [f"cd /ca && ./easyrsa --batch sign-req {cert_type_arg} {common_name}"]
        )

        if not success:
            flash(f"Failed to sign certificate: {output}")
            return redirect(url_for("generate_certificate"))

        # Get the certificate serial number
        success, serial_output = run_ca_command(
            [
                f"openssl x509 -in {app.config['CA_PATH']}/pki/issued/{common_name}.crt -serial -noout"
            ]
        )

        if not success:
            flash(f"Failed to get certificate serial: {serial_output}")
            return redirect(url_for("generate_certificate"))

        serial_number = serial_output.split("=")[1].strip()

        # Get the certificate expiry date
        success, expiry_output = run_ca_command(
            [
                f"openssl x509 -in {app.config['CA_PATH']}/pki/issued/{common_name}.crt -enddate -noout"
            ]
        )

        if not success:
            flash(f"Failed to get certificate expiry: {expiry_output}")
            return redirect(url_for("generate_certificate"))

        expiry_str = expiry_output.split("=")[1].strip()
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        # Store certificate in database
        new_cert = Certificate(
            common_name=common_name,
            serial_number=serial_number,
            expiry_date=expiry_date,
            certificate_type=cert_type,
            user_id=current_user.id if cert_type == "user" else None,
        )

        db.session.add(new_cert)
        db.session.commit()

        # Prepare certificate and key for download
        temp_dir = tempfile.mkdtemp()
        try:
            # Copy certificate and key to temp directory
            shutil.copy(
                os.path.join(app.config["CA_PATH"], "pki/issued", f"{common_name}.crt"),
                os.path.join(temp_dir, f"{common_name}.crt"),
            )
            shutil.copy(
                os.path.join(
                    app.config["CA_PATH"], "pki/private", f"{common_name}.key"
                ),
                os.path.join(temp_dir, f"{common_name}.key"),
            )

            # Create a zip file
            zip_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{common_name}.zip")
            shutil.make_archive(
                os.path.join(app.config["UPLOAD_FOLDER"], common_name), "zip", temp_dir
            )

            flash(f"Certificate for {common_name} generated successfully")
            return redirect(
                url_for("download_certificate", filename=f"{common_name}.zip")
            )

        finally:
            # Clean up
            shutil.rmtree(temp_dir)

    return render_template("generate_certificate.html")


@app.route("/download_certificate/<filename>")
@login_required
def download_certificate(filename):
    return send_file(
        os.path.join(app.config["UPLOAD_FOLDER"], filename), as_attachment=True
    )


@app.route("/revoke_certificate/<int:cert_id>", methods=["POST"])
@login_required
def revoke_certificate(cert_id):
    cert = Certificate.query.get_or_404(cert_id)

    # Only admins or the certificate owner can revoke
    if current_user.username != "admin" and cert.user_id != current_user.id:
        flash("You don't have permission to revoke this certificate")
        return redirect(url_for("certificates"))

    # Revoke the certificate
    success, output = run_ca_command(
        [f"cd /ca && ./easyrsa --batch revoke {cert.common_name}"]
    )

    if not success:
        flash(f"Failed to revoke certificate: {output}")
        return redirect(url_for("certificates"))

    # Generate new CRL
    success, output = run_ca_command([f"cd /ca && ./easyrsa gen-crl"])

    if not success:
        flash(f"Failed to generate CRL: {output}")
        return redirect(url_for("certificates"))

    # Update certificate status in database
    cert.is_revoked = True
    cert.revocation_date = datetime.utcnow()
    db.session.commit()

    flash(f"Certificate {cert.common_name} has been revoked")
    return redirect(url_for("certificates"))


@app.route("/recover_certificate/<int:cert_id>", methods=["POST"])
@login_required
def recover_certificate(cert_id):
    # Get the original certificate from the database
    cert = Certificate.query.get_or_404(cert_id)

    # Only admins or the certificate owner can recover
    if current_user.username != "admin" and cert.user_id != current_user.id:
        flash("You don't have permission to recover this certificate")
        return redirect(url_for("certificates"))

    # Simply mark the old certificate as revoked in our database
    # Don't try to do anything with it in the CA system
    cert.is_revoked = True
    cert.revocation_date = datetime.utcnow()
    db.session.commit()

    # Generate a new certificate with a unique name
    # Use timestamp to ensure uniqueness
    recovery_common_name = (
        f"new_{cert.common_name}_{int(datetime.utcnow().timestamp())}"
    )

    # Generate completely new certificate
    success, output = run_ca_command(
        [
            f"cd /ca && ./easyrsa --batch --req-cn='{recovery_common_name}' gen-req {recovery_common_name} nopass"
        ]
    )

    if not success:
        flash(f"Failed to generate new certificate request: {output}")
        return redirect(url_for("certificates"))

    # Sign the new certificate
    cert_type_arg = "client" if cert.certificate_type == "user" else "server"
    success, output = run_ca_command(
        [f"cd /ca && ./easyrsa --batch sign-req {cert_type_arg} {recovery_common_name}"]
    )

    if not success:
        flash(f"Failed to sign new certificate: {output}")
        return redirect(url_for("certificates"))

    # Get the new certificate serial number
    success, serial_output = run_ca_command(
        [
            f"openssl x509 -in {app.config['CA_PATH']}/pki/issued/{recovery_common_name}.crt -serial -noout"
        ]
    )

    if not success:
        flash(f"Failed to get certificate serial: {serial_output}")
        return redirect(url_for("certificates"))

    serial_number = serial_output.split("=")[1].strip()

    # Get the new certificate expiry date
    success, expiry_output = run_ca_command(
        [
            f"openssl x509 -in {app.config['CA_PATH']}/pki/issued/{recovery_common_name}.crt -enddate -noout"
        ]
    )

    if not success:
        flash(f"Failed to get certificate expiry: {expiry_output}")
        return redirect(url_for("certificates"))

    expiry_str = expiry_output.split("=")[1].strip()
    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

    # Store new certificate in database with same attributes as old one
    new_cert = Certificate(
        common_name=recovery_common_name,
        serial_number=serial_number,
        expiry_date=expiry_date,
        certificate_type=cert.certificate_type,
        user_id=cert.user_id,
    )

    db.session.add(new_cert)
    db.session.commit()

    # Prepare certificate and key for download
    temp_dir = tempfile.mkdtemp()
    try:
        # Copy new certificate and key to temp directory
        shutil.copy(
            os.path.join(
                app.config["CA_PATH"], "pki/issued", f"{recovery_common_name}.crt"
            ),
            os.path.join(temp_dir, f"{recovery_common_name}.crt"),
        )
        shutil.copy(
            os.path.join(
                app.config["CA_PATH"], "pki/private", f"{recovery_common_name}.key"
            ),
            os.path.join(temp_dir, f"{recovery_common_name}.key"),
        )

        # Create a zip file of the new certificate
        zip_path = os.path.join(
            app.config["UPLOAD_FOLDER"], f"{recovery_common_name}.zip"
        )
        shutil.make_archive(
            os.path.join(app.config["UPLOAD_FOLDER"], recovery_common_name),
            "zip",
            temp_dir,
        )

        flash(f"New certificate generated successfully to replace the old one")
        return redirect(
            url_for("download_certificate", filename=f"{recovery_common_name}.zip")
        )

    finally:
        # Clean up
        shutil.rmtree(temp_dir)
        
        
@app.route("/users", methods=["GET"])
@login_required
def list_users():
    if current_user.username != "admin":
        flash("You don't have permission to view users")
        return redirect(url_for("dashboard"))

    users = User.query.all()
    return render_template("users.html", users=users)


@app.route("/users/new", methods=["GET", "POST"])
@login_required
def new_user():
    if current_user.username != "admin":
        flash("You don't have permission to create users")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash(f"Username {username} already exists")
            return redirect(url_for("new_user"))

        if User.query.filter_by(email=email).first():
            flash(f"Email {email} already exists")
            return redirect(url_for("new_user"))

        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash(f"User {username} created successfully")
        return redirect(url_for("list_users"))

    return render_template("new_user.html")

@app.route("/auth/certificate")
def cert_auth():
    # This route will be accessed when a user clicks "Certificate" button

    # Check if the certificate authentication was successful (via headers)
    client_verified = request.headers.get("X-SSL-Client-Verify")
    client_dn = request.headers.get("X-SSL-Client-DN")

    # Add debug log message
    logger.info(
        f"Certificate auth attempt - Verified: {client_verified}, DN: {client_dn}"
    )

    if client_verified == "SUCCESS" and client_dn:
        # Extract relevant information from the certificate DN
        cn = None
        for part in client_dn.split("/"):
            if part.startswith("CN="):
                cn = part[3:]
                break

        logger.info(f"Extracted CN from certificate: {cn}")

        if cn:
            # First try to find a user with this username
            user = User.query.filter_by(username=cn).first()

            # If not found by username, try to find a certificate with this common name
            if not user:
                logger.info(f"No user found with username {cn}, checking certificates")
                cert = Certificate.query.filter_by(
                    common_name=cn, is_revoked=False
                ).first()
                if cert and cert.user_id:
                    user = User.query.get(cert.user_id)
                    logger.info(f"Found user {user.username} via certificate {cn}")

            if user:
                login_user(user)
                flash(f"Successfully authenticated with certificate for {cn}")
                return redirect(url_for("dashboard"))
            else:
                logger.warning(f"No user found for certificate CN: {cn}")

    # If we reach here, authentication failed
    flash("Certificate authentication failed. Please try again or use password.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
