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
import datetime

# for database
import MySQLdb
from MySQLdb import escape_string as thwart

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
    )
)

# enable captcha
recaptcha = ReCaptcha()
recaptcha.init_app(app)


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

                    flash("You have successfully logged in!")
                    return redirect(url_for("dashboard"))

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

                return redirect(url_for('dashboard'))

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
