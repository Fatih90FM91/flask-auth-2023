import os

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['post', 'get'])
def register():
    if request.method == 'POST':
        users = User.query.all()
        all_emails = [item.email for item in users]
        if request.form['email'] not in all_emails:
            new_user = User(
                name=request.form['name'],
                email=request.form['email'],
                password=generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8), #password was hashed pbkdf2:sha256:260000$ChTMvA8J$d8b6c6210f410438e7f200cd010751d695abf059902973ae6f96bf9949372036

            )
            db.session.add(new_user)
            db.session.commit()

            return render_template('secrets.html', name=new_user.name, logged_in=True)

        else:
            flash('the email is already used before. Please try others!!')
            return render_template('login.html')






    return render_template("register.html")


@app.route('/login',  methods=['GET', 'POST'])
# @login_required
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        print(user)

        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                flash('Logged in successfully.')
                return render_template('secrets.html', name=user.name, logged_in=True)
            else:

                if request.form['email'] != user.email or \
                        request.form['password'] != user.password:
                    flash('Wrong password or email. Keep try again..!!')
                else:
                    flash('You were successfully logged in')
                    return redirect(url_for('/'))

        else:

            flash('The User does not exist. Try again please!!')

        # Login and validate the user.
        # user should be an instance of your `User` class


    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/static/<path:path>', methods=['GET'])
def download(path):
    return send_from_directory('static', filename=path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
