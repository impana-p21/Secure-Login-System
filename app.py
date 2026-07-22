from flask import Flask,render_template,request,redirect,session
import sqlite3
import bcrypt
import random

app=Flask(__name__)
app.secret_key="secret123"

conn=sqlite3.connect(
"users.db",
check_same_thread=False
)

cursor=conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT
)
""")

conn.commit()

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register",methods=["GET","POST"])
def register():

    message=""

    if request.method=="POST":

        username=request.form["username"].strip()
        password=request.form["password"]

        if len(username)<3:
            message="Username too short."

        elif len(password)<6:
            message="Password too short."

        else:

            hashed=bcrypt.hashpw(
                password.encode(),
                bcrypt.gensalt()
            )

            try:

                cursor.execute(
                "INSERT INTO users(username,password) VALUES(?,?)",
                (username,hashed)
                )

                conn.commit()

                return redirect("/login")

            except:
                message="Username already exists."

    return render_template(
        "register.html",
        message=message
    )

@app.route("/login",methods=["GET","POST"])
def login():

    message=""

    if request.method=="POST":

        username=request.form["username"]
        password=request.form["password"]

        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )

        user=cursor.fetchone()

        if user and bcrypt.checkpw(
            password.encode(),
            user[0]
        ):

            otp=str(random.randint(100000,999999))

            print("OTP:",otp)

            session["otp"]=otp
            session["pending_user"]=username

            return redirect("/verify")

        message="Invalid Credentials."

    return render_template(
        "login.html",
        message=message
    )

@app.route("/verify",methods=["GET","POST"])
def verify():

    message=""

    if request.method=="POST":

        if request.form["otp"]==session.get("otp"):

            session["user"]=session["pending_user"]

            session.pop("otp",None)
            session.pop("pending_user",None)

            return redirect("/dashboard")

        message="Invalid OTP."

    return render_template(
        "verify.html",
        message=message
    )

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["user"]
    )

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

if __name__=="__main__":
    app.run(debug=True)
