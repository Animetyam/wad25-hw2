import os
from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Length
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config["MONGO_URI"] = "mongodb://localhost:27017/MyDatabase"
mongo = PyMongo(app)
login = LoginManager(app)
login.login_view = 'startPage'
UPLOAD_FOLDER = 'static/profilePictures'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class User(UserMixin):
    def __init__(self, user_id, username, password_hash, about_me, profile_pic):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.about_me = about_me
        self.profile_pic = profile_pic
    
    @staticmethod
    def get_user_by_username(username):
        user_data = mongo.db.users.find_one({"username": username})
        if user_data:
            return User(user_data["user_id"], user_data["username"], user_data["password_hash"], user_data["about_me"], user_data["profile_pic"])
        return None

@app.route("/", methods=['GET', 'POST'])
def startPage():
    if current_user.is_authenticated:
        return redirect(url_for('profPage'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_user_by_username(form.username.data)
        if user is None:
            flash('Invalid username')
            return redirect(url_for('startPage'))
        if not check_password_hash(user.password_hash, form.password.data):
            flash('Invalid password')
            return redirect(url_for('startPage'))
        login_user(user)
        return redirect(url_for('profPage'))
    
    return render_template('startPage.html', title='Sign In', form=form)

@app.route("/profile")
@login_required
def profPage():
    return render_template('profPage.html')

@login.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"user_id": user_id})
    if user_data:
        return User(user_data["user_id"], user_data["username"], user_data["password_hash"], user_data["about_me"], user_data["profile_pic"])
    return None

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('startPage'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profPage'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user_data = {
            "user_id": str(mongo.db.users.count_documents({})),
            "username": form.username.data,
            "password_hash": generate_password_hash(form.password.data, method='pbkdf2:sha256'), 
            "about_me": "Information about you",
            "profile_pic": "defaultProfile.png" 
        }
        mongo.db.users.insert_one(new_user_data)
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('startPage'))
    return render_template('register.html', title='Register', form=form)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user_data = mongo.db.users.find_one({"username": username.data})
        if user_data:
            raise ValidationError('Please use a different username.')
        
class EditProfileForm(FlaskForm):
    password = PasswordField('New Password')
    password2 = PasswordField('Repeat new Password', validators=[EqualTo('password')])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=50)])
    image = FileField('New profile picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Submit')

@app.route('/editProfile', methods=['GET', 'POST'])
@login_required
def editProfile():
    form = EditProfileForm()
    if form.validate_on_submit():
        filter = {'username': current_user.username}
        if form.password.data:
            new_pass = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        else:
            new_pass=current_user.password_hash
        if form.about_me.data:
            new_about = form.about_me.data
        else:
            new_about = current_user.about_me.data
        if form.image.data:
            filename = form.image.data.filename
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = current_user.profile_pic
        new_values = {'$set': {'password_hash': new_pass, 'about_me': new_about, 'profile_pic': filename}}
        mongo.db.users.update_many(filter, new_values)
        flash('Your changes have been saved.')
        return redirect(url_for('editProfile'))
    elif request.method == 'GET':
        form.about_me.data = current_user.about_me
    return render_template('editProfile.html', title='Edit Profile', form=form)

if __name__ == "__main__": 
    app.run()
