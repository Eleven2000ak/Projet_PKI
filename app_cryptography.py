from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder, ReasonFlags
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'

# === Configuration des chemins ===
PKI_ROOT = 'pki'
CERTS_DIR = os.path.join(PKI_ROOT, 'final-certs')
CA_DIR = os.path.join(PKI_ROOT, 'intermediateCA')
CRL_PATH = os.path.join(PKI_ROOT, 'crl', 'intermediate.crl.pem')

# === Fonctions utilitaires ===
def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key_to_file(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def create_csr(key, common_name):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())

def save_csr_to_file(csr, path):
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

def get_all_files(extension):
    return [f for f in os.listdir(CERTS_DIR) if f.endswith(extension)]

# === Routes ===
@app.route('/')
def index():
    return render_template('index.html', now=datetime.now())

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        cn = request.form.get('common_name')
        validity = int(request.form.get('validity', '365'))
        if not cn:
            flash("Le champ Common Name est requis.", "error")
            return redirect(url_for('generate'))

        os.makedirs(CERTS_DIR, exist_ok=True)
        key_path = os.path.join(CERTS_DIR, f"{cn}.key.pem")
        csr_path = os.path.join(CERTS_DIR, f"{cn}.csr.pem")

        key = generate_key()
        save_key_to_file(key, key_path)
        csr = create_csr(key, cn)
        save_csr_to_file(csr, csr_path)

        flash("Clé privée et CSR générés avec succès.", "success")
        return redirect(url_for('index'))

    return render_template('generate.html')

@app.route('/csrs')
def view_csrs():
    csrs = get_all_files('.csr.pem')
    return render_template('csrs.html', csrs=csrs)

@app.route('/sign/<filename>')
def sign_csr(filename):
    csr_path = os.path.join(CERTS_DIR, filename)
    cert_path = csr_path.replace('.csr.pem', '.crt.pem')
    cert_name = filename.replace('.csr.pem', '')

    intermediate_cert = os.path.join(CA_DIR, 'intermediate.cert.pem')
    intermediate_key = os.path.join(CA_DIR, 'intermediate.key.pem')

    if not os.path.exists(intermediate_cert) or not os.path.exists(intermediate_key):
        flash("Fichiers CA intermédiaire manquants.", "error")
        return redirect(url_for('view_csrs'))

    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    with open(intermediate_cert, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(intermediate_key, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    cert = x509.CertificateBuilder()\
        .subject_name(csr.subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(csr.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256())

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    flash("Certificat signé avec succès.", "success")
    return redirect(url_for('view_csrs'))

@app.route('/certs')
def list_certs():
    certs = get_all_files('.crt.pem')
    return render_template('certs.html', certs=certs)

@app.route('/revoke/<filename>')
@app.route('/revoke/<filename>')
def revoke_cert(filename):
    cert_path = os.path.join(CERTS_DIR, filename)
    intermediate_cert = os.path.join(CA_DIR, 'intermediate.cert.pem')
    intermediate_key = os.path.join(CA_DIR, 'intermediate.key.pem')

    if not os.path.exists(cert_path):
        flash("Certificat introuvable.", "error")
        return redirect(url_for('index'))

    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        with open(intermediate_cert, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(intermediate_key, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        # Charger les certificats déjà révoqués
        revoked_list = []
        if os.path.exists(CRL_PATH):
            with open(CRL_PATH, "rb") as f:
                old_crl = x509.load_pem_x509_crl(f.read())
            revoked_list.extend(old_crl)

        # Ajouter le certificat actuel
        new_revoked = RevokedCertificateBuilder()\
            .serial_number(cert.serial_number)\
            .revocation_date(datetime.utcnow())\
            .add_extension(x509.CRLReason(ReasonFlags.key_compromise), critical=False)\
            .build()

        # Reconstruire la CRL avec tous les certificats révoqués
        crl_builder = CertificateRevocationListBuilder()\
            .issuer_name(ca_cert.subject)\
            .last_update(datetime.utcnow())\
            .next_update(datetime.utcnow() + timedelta(days=30))

        for revoked in revoked_list:
            crl_builder = crl_builder.add_revoked_certificate(revoked)

        crl_builder = crl_builder.add_revoked_certificate(new_revoked)

        crl = crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

        os.makedirs(os.path.dirname(CRL_PATH), exist_ok=True)
        with open(CRL_PATH, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        flash("Certificat révoqué avec succès. CRL mise à jour.", "success")

    except Exception as e:
        flash(f"Erreur lors de la révocation : {str(e)}", "error")

    return redirect(url_for('index'))

@app.route('/verify', methods=['GET', 'POST'])
def verify_cert():
    certs = get_all_files('.crt.pem')
    result = error = None

    if request.method == 'POST':
        filename = request.form.get('cert_name')
        cert_path = os.path.join(CERTS_DIR, filename)
        ca_cert_path = os.path.join(CA_DIR, 'intermediate.cert.pem')

        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())

            now = datetime.utcnow()
            is_valid = cert.not_valid_before <= now <= cert.not_valid_after
            is_signed = cert.issuer == ca_cert.subject
            is_revoked = False

            if os.path.exists(CRL_PATH):
                with open(CRL_PATH, "rb") as f:
                    crl = x509.load_pem_x509_crl(f.read())
                is_revoked = any(rc.serial_number == cert.serial_number for rc in crl)

            if not is_valid:
                result = "Le certificat est expiré ou pas encore actif."
            elif not is_signed:
                result = "Le certificat n'est pas signé par la CA intermédiaire."
            elif is_revoked:
                result = "Le certificat est révoqué."
            else:
                result = "Le certificat est valide et de confiance."

        except Exception as e:
            error = f"Erreur : {str(e)}"

    return render_template('verify.html', certs=certs, result=result, error=error)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(CERTS_DIR, filename, as_attachment=True)

@app.route('/dashboard')
def dashboard():
    certs = get_all_files('.crt.pem')
    csrs = get_all_files('.csr.pem')
    revoked = 0
    valid = 0
    now = datetime.utcnow()

    if os.path.exists(CRL_PATH):
        with open(CRL_PATH, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        revoked = len(crl)

    for cert_file in certs:
        with open(os.path.join(CERTS_DIR, cert_file), "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        if cert.not_valid_before <= now <= cert.not_valid_after:
            valid += 1

    return render_template("dashboard.html",
                           certs_count=len(certs),
                           csrs_count=len(csrs),
                           revoked_count=revoked,
                           valid_count=valid)

if __name__ == '__main__':
    app.run(debug=True)
