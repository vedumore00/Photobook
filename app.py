from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)
app.secret_key = "super-secret-key"

# ================= AWS CONFIG =================
REGION = "us-east-1"
AWS_ENABLED = False   # 🔴 SET True when AWS credentials are configured
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:BookingNotifications"

# ================= AWS / LOCAL SETUP =================
if AWS_ENABLED:
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    sns = boto3.client("sns", region_name=REGION)

    users_table = dynamodb.Table("Users")       # PK: email
    admins_table = dynamodb.Table("Admins")     # PK: username
    bookings_table = dynamodb.Table("Bookings") # PK: id
else:
    # ---------- MOCK TABLES (LOCAL MODE) ----------
    class MockTable:
        def __init__(self):
            self.items = []

        def put_item(self, Item):
            self.items.append(Item)

        def get_item(self, Key):
            for i in self.items:
                if all(i.get(k) == v for k, v in Key.items()):
                    return {"Item": i}
            return {}

        def scan(self):
            return {"Items": self.items.copy()}

        def delete_item(self, Key):
            self.items = [
                i for i in self.items if not all(i.get(k) == v for k, v in Key.items())
            ]

    users_table = MockTable()
    admins_table = MockTable()
    bookings_table = MockTable()

    admins_table.put_item({
        "username": "admin",
        "password": generate_password_hash("admin123")
    })

    class MockSNS:
        def publish(self, **kwargs):
            app.logger.info("========== SNS MOCK ==========")
            app.logger.info("Subject: %s", kwargs.get("Subject"))
            app.logger.info("Message:\n%s", kwargs.get("Message"))
            app.logger.info("================================")

    sns = MockSNS()

# ================= SNS HELPER =================
def send_notification(subject, message):
    if not AWS_ENABLED:
        sns.publish(Subject=subject, Message=message)
        return
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        app.logger.error("SNS Error: %s", e)

# ================= MESSAGE FORMAT =================
def booking_confirmation_message(booking):
    return f"""
Hello {booking['name']},

Your booking has been successfully confirmed! 🎉

📸 Booking Details:
• Booking ID   : {booking['id']}
• Service Type : {booking['type']}
• Date         : {booking['date']}
• Time         : {booking['time']}
• Status       : {booking['status']}

If you have any questions or need to reschedule,
please contact our support team.

Thank you for choosing us!
— Photography Booking Team
"""

# ================= PUBLIC ROUTES =================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/photographers")
def photographers():
    return render_template("photographers.html")

# ================= BOOKINGS =================
@app.route("/bookings", methods=["GET", "POST"])
def bookings():
    if request.method == "POST":
        booking = {
            "id": str(uuid.uuid4()),
            "name": request.form.get("name"),
            "email": request.form.get("email"),
            "type": request.form.get("type"),
            "date": request.form.get("date"),
            "time": request.form.get("time"),
            "status": "Pending"
        }

        if not all(booking.values()):
            flash("All fields are required", "error")
            return redirect(url_for("bookings"))

        bookings_table.put_item(Item=booking)

        send_notification(
            subject="Booking Confirmation – Appointment Scheduled",
            message=booking_confirmation_message(booking)
        )

        flash("Booking submitted successfully!", "success")
        return redirect(url_for("availability"))

    return render_template("bookings.html")

# ================= AVAILABILITY =================
@app.route("/availability", methods=["GET", "POST"])
def availability():
    unavailable_slots = []

    if request.method == "POST":
        selected_date = request.form["date"]
        unavailable_slots = ["10:00 AM - 12:00 PM", "3:00 PM - 5:00 PM"]
        flash(f"Availability checked for {selected_date}", "success")

    return render_template("availability.html", unavailable_slots=unavailable_slots)

# ================= USER AUTH =================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("All fields are required", "error")
            return redirect(url_for("signup"))

        if "Item" in users_table.get_item(Key={"email": email}):
            flash("Email already registered.", "error")
            return redirect(url_for("signup"))

        users_table.put_item(Item={
            "email": email,
            "password": generate_password_hash(password)
        })

        send_notification("New User Signup", f"New user registered: {email}")
        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        res = users_table.get_item(Key={"email": email})
        if "Item" in res and check_password_hash(res["Item"]["password"], password):
            session["user"] = email
            send_notification("User Login", f"User logged in: {email}")
            return redirect(url_for("index"))

        flash("Invalid credentials.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ================= ADMIN =================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        res = admins_table.get_item(Key={"username": username})
        if "Item" in res and check_password_hash(res["Item"]["password"], password):
            session["admin"] = True
            send_notification("Admin Login", f"Admin logged in: {username}")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials", "error")

    return render_template("admin-auth.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    bookings = bookings_table.scan().get("Items", [])
    return render_template(
        "admin_dashboard.html",
        bookings=bookings,
        total_bookings=len(bookings)
    )

@app.route("/admin/delete_booking/<booking_id>", methods=["POST"])
def delete_booking(booking_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    bookings_table.delete_item(Key={"id": booking_id})
    send_notification("Booking Deleted", f"Booking ID {booking_id} deleted by admin")
    return redirect(url_for("admin_dashboard"))

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
