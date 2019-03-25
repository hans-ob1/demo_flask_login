from flask import Flask,\
                  render_template, \
                  flash, \
                  request, \
                  session, \
                  redirect, \
                  url_for

from flask_recaptcha import ReCaptcha
from passlib.hash import sha256_crypt
from functools import wraps

import gc
import os
import datetime

# for database
import MySQLdb
from MySQLdb import escape_string as thwart

# email validation
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

# get forms 
from _forms import UserRegistrationForm


# -------- app initialization ----------------
app = Flask(__name__)
app.config.update(
    dict(
        SECRET_KEY=b'samplekey2019',
        SECURITY_PASSWORD_SALT='samplekey2019',

        RECAPTCHA_ENABLED = True,

        # these keys are for testing, replace with real keys in your deployment server
        RECAPTCHA_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
        RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",

        # mail settings
        MAIL_SERVER = 'smtp.googlemail.com',
        MAIL_PORT = 465,
        MAIL_USE_TLS = False,
        MAIL_USE_SSL = True,

        # gmail authentication
        MAIL_USERNAME = os.environ['APP_MAIL_USERNAME'],
        MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD'],

        # mail accounts
        MAIL_DEFAULT_SENDER = 'no-reply@aisingapore.org'
    )
)

# enable captcha
recaptcha = ReCaptcha()
recaptcha.init_app(app)

# setup mailing
mail = Mail(app)

# ------------> support functions <--------------
# ** database connection
def connection():
    conn = MySQLdb.connect(host = "localhost",
                           user = "root",
                           passwd = "asd123",
                           db = "demo_db")

    c = conn.cursor()
    return c, conn

# ** login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
			#DEBUG
            flash("You need to login first")
            return redirect(url_for('login'))
    return wrap

# ** token validation
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

# ** confirm token
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

# ** email function
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
# -------------< support functions >--------------



# Login
@app.route('/', methods = ['GET','POST'])
def login():

    error = ''
    try:
        c, conn = connection()

        if request.method == "POST":

            data = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(request.form['username']),))
            data = c.fetchone()

            if data != None:

                data = data[4]	# obtain password hash, in this case its at index 3

                if sha256_crypt.verify(request.form['password'], data):
                    session['logged_in'] = True
                    session['username'] = request.form['username']

                    return redirect(url_for("unconfirmed"))

                else:
                    error = "Invalid credentials, try again."
            else:
                error = "Invalid credentials, no such user."

        # garbage collection
        conn.close()
        gc.collect()

        return render_template("login.html", error = error)

    except Exception as e:
        return str(e)


# Signup
@app.route('/register/', methods=["GET", "POST"])
def register():
    try:
        form = UserRegistrationForm(request.form)

        if request.method == "POST" and form.validate() and recaptcha.verify():

            # collect information from form
            username = form.username.data
            firstname = form.firstname.data
            lastname = form.lastname.data
            email = form.email.data
            password = sha256_crypt.encrypt((str(form.password.data)))

            c, conn = connection()
            x = c.execute("SELECT * FROM users WHERE username = (%s)", (thwart(username),))
            y = c.execute("SELECT * FROM users WHERE email = (%s)", (thwart(email),))

            if int(x) > 0:
                flash("Username already taken")
                return render_template('signup.html', form=form)
            elif int(y) > 0:
                flash("This email address is already registered")
                return render_template('signup.html', form=form)				
            else:
                c.execute("INSERT INTO users (firstname, \
                                              lastname, \
                                              username, \
                                              password, \
                                              email, \
                                              usertype, \
                                              isactive) \
                                              VALUES (%s, %s, %s, %s, %s, %s, %s)",
						                      (thwart(firstname), 
                                               thwart(lastname), 
                                               thwart(username), 
                                               thwart(password), 
                                               thwart(email), 
                                               thwart('author'),
                                               thwart('0'),
                                               ))

                flash("Thank you for registering")
                # saving your change to database!
                conn.commit()

                c.close()
                conn.close()

                # garbage collection
                gc.collect()

                session['logged_in'] = True
                session['username'] = username

                # email confirmation part
                token = generate_confirmation_token(email)
                confirm_url = url_for('confirm_email', token=token, _external=True)
                html = render_template('user/activate.html', confirm_url=confirm_url)
                subject = "Email Confirmation"
                send_email(email,subject,html)

                return redirect(url_for('unconfirmed'))

        return render_template("signup.html", form=form)

    except Exception as e:
        return str(e)


# dashboard
@app.route('/dashboard/', methods=["GET", "POST"])
@login_required
def dashboard():

    try:
        c, conn = connection()
        curr_user = session['username']

        data = c.execute("SELECT usertype FROM users WHERE username=(%s)", (thwart(curr_user),))
        data = c.fetchone()

        post_data = {}
        post_data['usertype'] = ''

        if data != None:

            # update user type
            post_data['usertype'] = data[0]

        conn.close()
        gc.collect()
        
        return render_template("dashboard.html", post_data=post_data)

    except Exception as e:
        return str(e)


# Email Confirmation
@app.route('/confirm-email/<token>')
@login_required
def confirm_email(token):

    try:
        c, conn = connection()
        try:
            # get back our email address from the token
            email = confirm_token(token)
        except Exception as e:
            flash("Confirmation link is invalid or expired.","danger")

        userData = c.execute("SELECT isactive, userID FROM users WHERE email=(%s)", (thwart(email),))
        userData = c.fetchone()

        if userData != None:
            if userData[0] == 1:
                flash("Account already validated. Please login.", "success")
            else:
                # update user status
                user_activate = 1
                c.execute("UPDATE users SET isactive=(%s) WHERE email=(%s)", (thwart(user_activate),thwart(email),))

                # gc
                conn.commit()
                c.close()
                conn.close()
                gc.collect()

                flash("You have successfully confirmed your account")     
        else:
            flash("Invalid link or token")
        
        return redirect(url_for('login'))
    except Exception as e:
        return str(e)

# unconfirmed route
@app.route('/unconfirmed')
@login_required
def unconfirmed():

    try:
        c, conn = connection()
        curr_user = session['username']

        userData = c.execute("SELECT isactive FROM users WHERE username=(%s)", (thwart(curr_user),))
        userData = c.fetchone()

        if userData != None:
            isactivate = userData[0]
            if isactivate == 1:
                return redirect(url_for('dashboard'))
            
            flash('Please activate your account first!')
            return render_template('user/unconfirmed.html')

    except Exception as e:
        return str(e)

# Logout
@app.route("/logout/")
@login_required
def logout():
    session.clear()
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for('login'))


# page not found handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")


if __name__ == "__main__":
    app.run(debug=False)
