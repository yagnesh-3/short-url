from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    long_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<URL id={self.id} long_url={self.long_url} short_url={self.short_url} user_id={self.user_id}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print("called")
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid Username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_urls = URL.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', urls=user_urls)

@app.route('/edit/<int:id>', methods=['GET'])
@login_required
def edit(id):
    url = URL.query.get_or_404(id)
    if url.user_id != current_user.id:
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', urls=URL.query.filter_by(user_id=current_user.id).all(), edit_url=url)

@app.route('/update/<int:id>', methods=['POST'])
@login_required
def update_url(id):
    url = URL.query.get_or_404(id)
    if url.user_id != current_user.id:
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    url.long_url = request.form['original_url']
    url.short_url = request.form['custom_short_url']
    db.session.commit()
    flash("Short URL updated successfully", "success")
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:url_id>', methods=['GET', 'POST'])
@login_required
def delete_url(url_id):
    url = URL.query.get_or_404(url_id)
    if url.user_id != current_user.id:
        flash("You don't have permission to delete this URL", "danger")
        return redirect(url_for('dashboard'))

    db.session.delete(url)
    db.session.commit()
    flash("URL deleted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        long_url = request.form['long_url']
        short_url = request.form['short_url']

        if not long_url.startswith(('http://', 'https://')):
            long_url = 'https://' + long_url

        if URL.query.filter_by(short_url=short_url).first():
            flash('Short URL already exists. Try another.', 'danger')
            return render_template('index.html', par=[False, ""])
        else:
            new_url = URL(long_url=long_url, short_url=short_url, user_id=current_user.id)
            db.session.add(new_url)
            db.session.commit()
            flash(f"Short URL created: {request.url_root}{short_url}", 'success')
            return render_template('index.html', par=[True, short_url])

    return render_template('index.html', par=[])

@app.route('/<short_url>')
def redirect_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first()
    if url:
        return redirect(url.long_url)
    else:
        flash("URL not found!", "danger")
        return redirect(url_for('index'))

@app.route('/create', methods=['POST'])
@login_required
def create():
    original_url = request.form['original_url']
    custom_short = request.form.get('custom_short_url', '').strip()

    if URL.query.filter_by(short_url=custom_short).first():
        flash('Short URL already exists. Try another.', 'danger')
        return redirect(url_for('dashboard'))

    new_url = URL(long_url=original_url, short_url=custom_short, user_id=current_user.id)
    db.session.add(new_url)
    db.session.commit()

    flash(f"Short URL created: {request.url_root}{custom_short}", 'success')
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(debug=True, host="0.0.0.0", port=port)
