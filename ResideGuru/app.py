from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reside_guru.db'
db = SQLAlchemy(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_provider = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('services', lazy=True))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewer = db.relationship('User', foreign_keys=[reviewer_id])
    provider = db.relationship('User', foreign_keys=[provider_id])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    services = Service.query.all()
    return render_template('index.html', services=services)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_provider = 'is_provider' in request.form

        user = User(username=username, email=email, is_provider=is_provider)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/request_service', methods=['GET', 'POST'])
@login_required
def request_service():
    if request.method == 'POST':
        category = request.form['category']
        description = request.form['description']
        location = request.form['location']

        service = Service(category=category, description=description, location=location, user_id=current_user.id)
        db.session.add(service)
        db.session.commit()

        flash('Service request submitted successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('request_service.html')

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        content = request.form['content']
        message = Message(content=content, sender_id=current_user.id, receiver_id=user_id)
        db.session.add(message)
        db.session.commit()
        flash('Message sent.', 'success')
        return redirect(url_for('chat', user_id=user_id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()

    return render_template('chat.html', user=user, messages=messages)

@app.route('/review/<int:provider_id>', methods=['GET', 'POST'])
@login_required
def review(provider_id):
    provider = User.query.get_or_404(provider_id)
    if request.method == 'POST':
        content = request.form['content']
        rating = int(request.form['rating'])
        review = Review(content=content, rating=rating, reviewer_id=current_user.id, provider_id=provider_id)
        db.session.add(review)
        db.session.commit()
        flash('Review submitted successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('review.html', provider=provider)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

