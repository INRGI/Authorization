from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user
from wtforms_alchemy import ModelForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.secret_key = "SECRET"

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String)

db.init_app(app)
with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    return "Ви не увійшли"

class UserForm(ModelForm):
    class Meta:
        model = User

class UserRegistrationForm(FlaskForm):
    login = StringField('Login', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_login(self, login):
        user = User.query.filter_by(login=login.data).first()
        if user is not None:
            raise ValidationError('Please use a different login.')

@app.route('/register', methods=["POST","GET"])
def register():
    form = UserRegistrationForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User(login=form.login.data, password=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect('/')
    return render_template('registration.html', form=form)

@app.route('/login', methods=["POST","GET"])
def login():
    form = UserForm()
    if request.method == "POST":
        form_data = request.form
        user =User.query\
               .filter(User.login == form_data.get("login"))\
               .filter(User.password == form_data.get("password"))\
               .first()
        if user and check_password_hash(user.password, form_data.get("password")):
            login_user(user)
            return redirect('/')
    return render_template('login.html', form=form)


@app.route('/')
@login_required
def index():
    return render_template('index.html')

app.run()
