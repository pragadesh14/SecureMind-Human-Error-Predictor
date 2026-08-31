from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import csv, io, random

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securemind.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    xp = db.Column(db.Integer, default=0)
    streak = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Scenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    difficulty = db.Column(db.String(30), default="Medium")
    description = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text, nullable=False)
    safest_option = db.Column(db.Integer, nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    risk_weight = db.Column(db.Integer, default=70)

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey("scenario.id"), nullable=False)
    response = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    ai_confidence = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scenario = db.relationship("Scenario")

def options(s): 
    import json
    return json.loads(s.options_json)

@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

def analyze(s, selected):
    # Explainable academic prototype: combines scenario severity and response safety.
    base = int(s.risk_weight)
    if selected == s.safest_option:
        score = max(5, round(base * 0.18))
        reason = "Your response follows the safer security practice for this situation."
        confidence = 92
    else:
        distance = abs(selected - s.safest_option)
        score = min(100, base + distance * 6 + random.randint(0, 6))
        reason = s.explanation
        confidence = min(96, 84 + distance * 3)
    level = "LOW" if score < 40 else ("MEDIUM" if score < 70 else "HIGH")
    return score, level, reason, s.recommendation, confidence

SEED = [
("Unexpected Email Attachment","Phishing","Easy",
 "You receive an unexpected email attachment from an unfamiliar sender. What should you do?",
 ["Open it immediately","Download it and scan it later","Verify the sender independently, then report/delete it"],2,
 "Unexpected attachments can contain malware or lead to credential theft. Treat unsolicited files as suspicious.",
 "Do not open the attachment. Verify the sender using a trusted channel and report the message.",78),
("Public Wi-Fi Login","Network Security","Easy",
 "You need to access your bank account while connected to free public Wi-Fi. What is safest?",
 ["Use the bank app over the public network","Use mobile data or a trusted VPN and verify the connection","Ask another person to connect your phone"],1,
 "Open public networks can expose traffic or enable malicious interception.",
 "Prefer mobile data or a trusted VPN and avoid sensitive transactions on untrusted networks.",82),
("Password Reuse","Password Security","Easy",
 "You have five accounts. What is the safest password strategy?",
 ["Use one strong password everywhere","Use unique passwords stored in a password manager","Use your birthday plus symbols"],1,
 "Password reuse allows one stolen password to unlock multiple services.",
 "Use unique passwords and a reputable password manager; enable MFA where available.",72),
("Unknown USB Drive","Device Security","Medium",
 "You find a USB drive in the college computer lab. What do you do?",
 ["Plug it in to identify the owner","Give it to IT/security without opening it","Plug it into your personal laptop"],1,
 "Unknown removable media can contain malware or malicious files.",
 "Do not connect unknown USB devices. Hand them to the appropriate IT/security staff.",88),
("Unexpected MFA Prompt","Account Security","Medium",
 "You receive an MFA approval prompt even though you are not logging in.",
 ["Approve it so the prompts stop","Deny it and change your password/check account activity","Ignore it forever"],1,
 "Unexpected MFA prompts can indicate that someone has your password and is attempting to sign in.",
 "Deny the request, change your password, review sessions, and report suspicious activity.",90),
("Fake IT Support Call","Social Engineering","Medium",
 "Someone claiming to be IT asks for your password to fix an urgent issue.",
 ["Give the password because they sound official","Refuse and contact IT through an official channel","Send a screenshot of your password"],1,
 "Attackers often create urgency and impersonate trusted staff to obtain credentials.",
 "Never disclose passwords. Verify the request using an official contact method.",94),
("Cloud Sharing Link","Data Protection","Medium",
 "A confidential project file must be shared with one teammate.",
 ["Make the file public and send the link","Share only with the teammate's verified account","Post the link in a public group"],1,
 "Public links can expose confidential information beyond the intended recipient.",
 "Use restricted, identity-based sharing and verify permissions before sending.",84),
("Browser Security Warning","Safe Browsing","Easy",
 "Your browser warns that a website certificate is invalid.",
 ["Continue anyway","Close the page and verify the correct website address","Disable browser security"],1,
 "Certificate warnings can indicate an unsafe connection, misconfiguration, or interception.",
 "Do not bypass security warnings. Verify the URL through a trusted source.",76),
("Suspicious QR Code","Phishing","Medium",
 "A poster contains a QR code offering a free gift and asks you to sign in.",
 ["Scan and enter your password","Verify the destination before opening and never enter credentials on an untrusted page","Forward it to friends"],1,
 "QR codes can hide phishing URLs and make malicious destinations harder to inspect.",
 "Inspect the destination and use the official website/app instead of entering credentials from an unknown QR code.",86),
("Suspicious SMS","Phishing","Easy",
 "You receive an SMS saying your account will be closed today unless you click a link.",
 ["Click immediately","Open the official app/site separately and check your account","Reply with your OTP"],1,
 "Urgent messages and links are common phishing techniques.",
 "Do not click the message link or share OTPs. Verify through the official service.",91),
("Software Download","Safe Browsing","Easy",
 "A popup says you have an outdated media player and offers an unknown download.",
 ["Install it immediately","Close the popup and update through the official source","Disable antivirus first"],1,
 "Fake update prompts are frequently used to distribute unwanted or malicious software.",
 "Install updates only through the operating system, official app, or trusted vendor.",87),
("Lost Smartphone","Mobile Security","Medium",
 "You lose a phone that contains work email and authenticator apps.",
 ["Wait a week to see if it returns","Use device tracking/remote lock and notify your organization","Post your passwords online"],1,
 "A lost device can expose accounts and sensitive data if it is not secured quickly.",
 "Remote-lock/wipe the device, notify the relevant organization, and secure affected accounts.",89),
("Wrong Recipient","Data Protection","Medium",
 "You are about to send a confidential document and notice the email recipient may be wrong.",
 ["Send it anyway","Stop and verify the recipient and attachment before sending","CC everyone"],1,
 "Sending sensitive information to the wrong recipient can cause data exposure.",
 "Pause and verify recipients, attachments, and permissions before sending.",83),
("Bluetooth Request","Mobile Security","Easy",
 "An unknown device requests a Bluetooth connection in a crowded place.",
 ["Accept automatically","Decline unless you can identify and trust the device","Share your contacts"],1,
 "Unexpected wireless pairing can create privacy and security risks.",
 "Decline unknown pairing requests and keep Bluetooth discoverability limited.",68),
("Fake Software Update","Device Security","Medium",
 "A website tells you to install a special security patch from an unfamiliar file.",
 ["Install it","Close the site and check for updates through official system settings","Disable security tools"],1,
 "Attackers can disguise malware as urgent security updates.",
 "Use official update mechanisms and do not install unexpected executables from websites.",93),
]

def seed():
    import json
    if Scenario.query.count() == 0:
        for row in SEED:
            db.session.add(Scenario(title=row[0], category=row[1], difficulty=row[2],
                description=row[3], options_json=json.dumps(row[4]), safest_option=row[5],
                explanation=row[6], recommendation=row[7], risk_weight=row[8]))
    if not User.query.filter_by(username="demo").first():
        db.session.add(User(username="demo", email="demo@securemind.local",
                            password_hash=generate_password_hash("demo123"), role="admin"))
    db.session.commit()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username, email, password = request.form["username"].strip(), request.form["email"].strip(), request.form["password"]
        if User.query.filter((User.username==username)|(User.email==email)).first():
            return render_template("auth.html", mode="register", error="Username or email already exists.")
        u=User(username=username,email=email,password_hash=generate_password_hash(password))
        db.session.add(u); db.session.commit(); login_user(u)
        return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=User.query.filter_by(username=request.form["username"].strip()).first()
        if u and check_password_hash(u.password_hash, request.form["password"]):
            login_user(u); return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="login", error="Invalid username or password.")
    return render_template("auth.html", mode="login")

@app.route("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    a=Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).all()
    avg=round(sum(x.risk_score for x in a)/len(a)) if a else 0
    safe=sum(x.risk_level=="LOW" for x in a)
    high=sum(x.risk_level=="HIGH" for x in a)
    return render_template("dashboard.html", assessments=a, avg=avg, safe=safe, high=high)

@app.route("/scenarios")
@login_required
def scenarios():
    q=request.args.get("q","").lower()
    cat=request.args.get("category","")
    items=Scenario.query.all()
    if q: items=[s for s in items if q in (s.title+" "+s.description+" "+s.category).lower()]
    if cat: items=[s for s in items if s.category==cat]
    cats=sorted({s.category for s in Scenario.query.all()})
    return render_template("scenarios.html", scenarios=items, categories=cats, q=q, cat=cat, options=options)

@app.route("/assessment/<int:sid>", methods=["GET","POST"])
@login_required
def assessment(sid):
    s=db.get_or_404(Scenario,sid)
    if request.method=="POST":
        selected=int(request.form["response"])
        score,level,reason,recommendation,confidence=analyze(s,selected)
        a=Assessment(user_id=current_user.id,scenario_id=s.id,response=options(s)[selected],
                     risk_score=score,risk_level=level,reason=reason,recommendation=recommendation,ai_confidence=confidence)
        db.session.add(a); current_user.xp += 25 if level=="LOW" else 15
        db.session.commit()
        return render_template("result.html", assessment=a, scenario=s)
    return render_template("assessment.html", scenario=s, options=options(s))

@app.route("/history")
@login_required
def history():
    items=Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()).all()
    return render_template("history.html", assessments=items)

@app.route("/recommendations")
@login_required
def recommendations():
    items=Assessment.query.filter_by(user_id=current_user.id).all()
    counts={}
    for a in items: counts[a.scenario.category]=counts.get(a.scenario.category,0)+a.risk_score
    weakest=sorted(counts.items(), key=lambda x:x[1], reverse=True)[:3]
    return render_template("recommendations.html", weakest=weakest, total=len(items))

@app.route("/profile")
@login_required
def profile():
    assessments=Assessment.query.filter_by(user_id=current_user.id).all()
    return render_template("profile.html", user=current_user, assessments=assessments)

@app.route("/admin")
@login_required
def admin():
    if current_user.role!="admin": return "Forbidden",403
    users=User.query.count(); assessments=Assessment.query.count()
    high=Assessment.query.filter_by(risk_level="HIGH").count()
    return render_template("admin.html", users=users, assessments=assessments, high=high, scenarios=Scenario.query.all())

@app.route("/export.csv")
@login_required
def export_csv():
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["Date","Scenario","Category","Response","Risk Score","Risk Level","Reason","Recommendation"])
    for a in Assessment.query.filter_by(user_id=current_user.id).order_by(Assessment.created_at.desc()):
        w.writerow([a.created_at.isoformat(),a.scenario.title,a.scenario.category,a.response,a.risk_score,a.risk_level,a.reason,a.recommendation])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=securemind-history.csv"})

@app.route("/api/stats")
@login_required
def api_stats():
    a=Assessment.query.filter_by(user_id=current_user.id).all()
    dist={"LOW":0,"MEDIUM":0,"HIGH":0}
    cats={}
    for x in a:
        dist[x.risk_level]+=1
        cats.setdefault(x.scenario.category,[]).append(x.risk_score)
    category={k:round(sum(v)/len(v)) for k,v in cats.items()}
    trend=[{"date":x.created_at.strftime("%d %b"),"score":x.risk_score} for x in a[-12:]]
    return jsonify({"distribution":dist,"category":category,"trend":trend})

with app.app_context():
    db.create_all()
    seed()

@app.route("/custom-assessment", methods=["GET", "POST"])
@login_required
def custom_assessment():
    if request.method == "POST":
        scenario_text = request.form.get("scenario", "").strip()

        if not scenario_text:
            return render_template(
                "custom_assessment.html",
                error="Please describe your security situation."
            )

        text = scenario_text.lower()

        # Risk indicators
        high_risk_words = [
            "password", "otp", "one time password", "bank",
            "credit card", "debit card", "money", "payment",
            "remote access", "unknown software", "malware",
            "ransomware", "admin access", "credential",
            "login", "verification code", "mfa code"
        ]

        medium_risk_words = [
            "public wifi", "unknown usb", "qr code",
            "unknown link", "attachment", "bluetooth",
            "email", "sms", "popup", "download",
            "social media", "cloud"
        ]

        safe_words = [
            "verify", "official", "trusted", "report",
            "delete", "block", "deny", "ignore",
            "security team", "it team"
        ]

        high_count = sum(1 for word in high_risk_words if word in text)
        medium_count = sum(1 for word in medium_risk_words if word in text)
        safe_count = sum(1 for word in safe_words if word in text)

        # Calculate risk score
        score = 25

        score += high_count * 12
        score += medium_count * 7
        score -= safe_count * 8

        score = max(5, min(100, score))

        if score < 40:
            level = "LOW"
        elif score < 70:
            level = "MEDIUM"
        else:
            level = "HIGH"

        # Generate explanation
        if level == "HIGH":
            reason = (
                "This situation contains indicators that could expose "
                "your account, credentials, personal information, or money "
                "to a security threat."
            )
        elif level == "MEDIUM":
            reason = (
                "This situation has some security warning signs. "
                "You should verify the request or source before taking action."
            )
        else:
            reason = (
                "The situation appears relatively low risk, but you should "
                "still follow normal security practices."
            )

        # DO recommendations
        do_list = [
            "Verify the person, message, website, or request using an official source.",
            "Use official applications or websites instead of unknown links.",
            "Enable multi-factor authentication where available.",
            "Report suspicious activity to the appropriate IT/security team."
        ]

        # DON'T recommendations
        dont_list = [
            "Do not share passwords, OTPs, MFA codes, or recovery codes.",
            "Do not open suspicious files or install unknown software.",
            "Do not bypass browser or security warnings.",
            "Do not provide sensitive information to an unverified person."
        ]

        # Adjust recommendations
        if "password" in text or "otp" in text or "verification code" in text:
            do_list.insert(
                0,
                "Change the affected password immediately if you believe it was exposed."
            )

        if "bank" in text or "payment" in text or "money" in text:
            do_list.insert(
                0,
                "Contact your bank or financial service through its official contact method."
            )

        return render_template(
            "custom_result.html",
            scenario=scenario_text,
            score=score,
            level=level,
            reason=reason,
            do_list=do_list,
            dont_list=dont_list
        )

    return render_template("custom_assessment.html")
if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)