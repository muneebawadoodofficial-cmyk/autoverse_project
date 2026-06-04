from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os
from functools import wraps

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'car-customizer-secret-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///car_customizer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================
# DATABASE MODELS
# =============================================

class User(db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    designs = db.relationship('Design', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Design(db.Model):
    """Design model for saving car customizations"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    car_model = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), default='My Design')
    
    # Customization properties
    body_color = db.Column(db.String(7), default='#FF0000')
    paint_finish = db.Column(db.String(20), default='glossy')
    window_tint = db.Column(db.Integer, default=0)
    wheel_style = db.Column(db.String(30), default='standard')
    suspension_height = db.Column(db.Float, default=0.0)
    headlight_color = db.Column(db.String(7), default='#FFFF00')
    headlight_enabled = db.Column(db.Boolean, default=True)
    engine_sound = db.Column(db.Boolean, default=False)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'car_model': self.car_model,
            'name': self.name,
            'body_color': self.body_color,
            'paint_finish': self.paint_finish,
            'window_tint': self.window_tint,
            'wheel_style': self.wheel_style,
            'suspension_height': self.suspension_height,
            'headlight_color': self.headlight_color,
            'headlight_enabled': self.headlight_enabled,
            'engine_sound': self.engine_sound,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class GalleryDesign(db.Model):
    """Public gallery designs"""
    id = db.Column(db.Integer, primary_key=True)
    car_model = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    designer = db.Column(db.String(100), default='Admin')
    
    body_color = db.Column(db.String(7))
    paint_finish = db.Column(db.String(20))
    wheel_style = db.Column(db.String(30))
    headlight_color = db.Column(db.String(7))
    
    featured = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'car_model': self.car_model,
            'name': self.name,
            'designer': self.designer,
            'body_color': self.body_color,
            'paint_finish': self.paint_finish,
            'wheel_style': self.wheel_style,
            'headlight_color': self.headlight_color,
            'featured': self.featured,
            'views': self.views
        }

# =============================================
# HELPER FUNCTIONS
# =============================================

def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def get_current_user():
    """Get current user object"""
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def login_required(f):
    """Decorator for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =============================================
# ROUTES - AUTHENTICATION
# =============================================

@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    from flask import send_from_directory
    try:
        return send_from_directory(os.path.join(app.root_path), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    except:
        return '', 204

@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html', is_logged_in=is_logged_in(), username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password required', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('car_selection'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

# =============================================
# ROUTES - MAIN FEATURES
# =============================================

@app.route('/car-selection')
@login_required
def car_selection():
    """Car selection page"""
    cars = [
        {
            'id': 'bmw-m4',
            'name': 'BMW M4',
            'description': 'Powerful German engineering with sleek design',
            'image': '/static/images/cars/bmw.jpg',
            'specs': 'Twin-Turbo V8, 503 HP, 0-60 in 3.9s'
        },
        {
            'id': 'audi-r8',
            'name': 'Audi R8',
            'description': 'Italian-inspired supercar from Audi',
            'image': '/static/images/cars/audi.jpg',
            'specs': 'V10 Engine, 610 HP, 0-60 in 3.2s'
        },
        {
            'id': 'ford-mustang',
            'name': 'Ford Mustang',
            'description': 'American muscle car icon',
            'image': '/static/images/cars/mustang.jpg',
            'specs': 'EcoBoost V6, 290 HP, 0-60 in 5.2s'
        },
        {
            'id': 'toyota-supra',
            'name': 'Toyota Supra',
            'description': 'Japanese sports car legend',
            'image': '/static/images/cars/supra.jpg',
            'specs': 'Twin-Turbo I6, 335 HP, 0-60 in 3.8s'
        }
    ]
    return render_template('car_selection.html', cars=cars, username=session.get('username'))

@app.route('/customizer/<car_model>')
@login_required
def customizer(car_model):
    """3D car customizer"""
    valid_cars = ['bmw-m4', 'audi-r8', 'ford-mustang', 'toyota-supra']
    if car_model not in valid_cars:
        flash('Invalid car model', 'error')
        return redirect(url_for('car_selection'))
    
    return render_template('customizer.html', car_model=car_model, username=session.get('username'))

@app.route('/garage')
@login_required
def garage():
    """User's personal garage"""
    user = get_current_user()
    designs = Design.query.filter_by(user_id=user.id).order_by(Design.created_at.desc()).all()
    return render_template('garage.html', designs=designs, username=session.get('username'))

@app.route('/gallery')
def gallery():
    """Public gallery"""
    page = request.args.get('page', 1, type=int)
    filter_car = request.args.get('car', None)
    
    if filter_car:
        gallery_designs = GalleryDesign.query.filter_by(car_model=filter_car).order_by(
            GalleryDesign.featured.desc(), 
            GalleryDesign.views.desc()
        ).paginate(page=page, per_page=12)
    else:
        gallery_designs = GalleryDesign.query.order_by(
            GalleryDesign.featured.desc(), 
            GalleryDesign.views.desc()
        ).paginate(page=page, per_page=12)
    
    return render_template('gallery.html', 
                         gallery_designs=gallery_designs,
                         filter_car=filter_car,
                         is_logged_in=is_logged_in(),
                         username=session.get('username'))

# =============================================
# API ENDPOINTS - DESIGNS
# =============================================

@app.route('/api/save-design', methods=['POST'])
@login_required
def save_design():
    """Save a design"""
    try:
        user = get_current_user()
        data = request.get_json()
        
        design = Design(
            user_id=user.id,
            car_model=data.get('car_model'),
            name=data.get('name', 'My Design'),
            body_color=data.get('body_color', '#FF0000'),
            paint_finish=data.get('paint_finish', 'glossy'),
            window_tint=data.get('window_tint', 0),
            wheel_style=data.get('wheel_style', 'standard'),
            suspension_height=data.get('suspension_height', 0.0),
            headlight_color=data.get('headlight_color', '#FFFF00'),
            headlight_enabled=data.get('headlight_enabled', True),
            engine_sound=data.get('engine_sound', False)
        )
        
        db.session.add(design)
        db.session.commit()
        
        return jsonify({'success': True, 'design_id': design.id, 'message': 'Design saved successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/designs', methods=['GET'])
@login_required
def get_designs():
    """Get all designs for current user"""
    try:
        user = get_current_user()
        designs = Design.query.filter_by(user_id=user.id).order_by(Design.created_at.desc()).all()
        return jsonify({'success': True, 'designs': [d.to_dict() for d in designs]}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/design/<int:design_id>', methods=['GET'])
@login_required
def get_design(design_id):
    """Get single design"""
    try:
        user = get_current_user()
        design = Design.query.get_or_404(design_id)
        
        if design.user_id != user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        return jsonify({'success': True, 'design': design.to_dict()}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/design/<int:design_id>', methods=['PUT'])
@login_required
def update_design(design_id):
    """Update design"""
    try:
        user = get_current_user()
        design = Design.query.get_or_404(design_id)
        
        if design.user_id != user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        design.name = data.get('name', design.name)
        design.body_color = data.get('body_color', design.body_color)
        design.paint_finish = data.get('paint_finish', design.paint_finish)
        design.window_tint = data.get('window_tint', design.window_tint)
        design.wheel_style = data.get('wheel_style', design.wheel_style)
        design.suspension_height = data.get('suspension_height', design.suspension_height)
        design.headlight_color = data.get('headlight_color', design.headlight_color)
        design.headlight_enabled = data.get('headlight_enabled', design.headlight_enabled)
        design.engine_sound = data.get('engine_sound', design.engine_sound)
        
        db.session.commit()
        
        return jsonify({'success': True, 'design': design.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/design/<int:design_id>', methods=['DELETE'])
@login_required
def delete_design(design_id):
    """Delete design"""
    try:
        user = get_current_user()
        design = Design.query.get_or_404(design_id)
        
        if design.user_id != user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        db.session.delete(design)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Design deleted'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/add-to-gallery', methods=['POST'])
@login_required
def add_to_gallery():
    """Add design to public gallery"""
    try:
        user = get_current_user()
        data = request.get_json()
        
        gallery_design = GalleryDesign(
            car_model=data.get('car_model'),
            name=data.get('name'),
            designer=user.username,
            body_color=data.get('body_color'),
            paint_finish=data.get('paint_finish'),
            wheel_style=data.get('wheel_style'),
            headlight_color=data.get('headlight_color')
        )
        
        db.session.add(gallery_design)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Design added to gallery'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400

# =============================================
# ERROR HANDLERS
# =============================================

@app.route('/model/<car_model>')
def get_model(car_model):
    """Serve 3D car models with correct headers"""
    import os
    from flask import send_file
    
    valid_models = ['bmw-m4', 'audi-r8', 'ford-mustang', 'toyota-supra']
    if car_model not in valid_models:
        return 'Invalid model', 400
    
    model_path = os.path.join('static', 'models', f'{car_model}.glb')
    
    if not os.path.exists(model_path):
        return 'Model not found', 404
    
    return send_file(
        model_path,
        mimetype='model/gltf-binary',
        as_attachment=False,
        download_name=f'{car_model}.glb'
    )

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

# =============================================
# INITIALIZATION
# =============================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Add sample gallery data if empty
        if GalleryDesign.query.count() == 0:
            sample_designs = [
                GalleryDesign(
                    car_model='bmw-m4',
                    name='Midnight Black Beast',
                    designer='Admin',
                    body_color='#000000',
                    paint_finish='matte',
                    wheel_style='sport',
                    headlight_color='#FFFF00',
                    featured=True,
                    views=45
                ),
                GalleryDesign(
                    car_model='audi-r8',
                    name='Crimson Racer',
                    designer='Admin',
                    body_color='#DC143C',
                    paint_finish='glossy',
                    wheel_style='premium',
                    headlight_color='#FFA500',
                    featured=True,
                    views=38
                ),
                GalleryDesign(
                    car_model='ford-mustang',
                    name='Classic Yellow',
                    designer='Admin',
                    body_color='#FFD700',
                    paint_finish='metallic',
                    wheel_style='classic',
                    headlight_color='#FFFF00',
                    featured=True,
                    views=52
                ),
                GalleryDesign(
                    car_model='toyota-supra',
                    name='Ocean Blue',
                    designer='Admin',
                    body_color='#0099FF',
                    paint_finish='glossy',
                    wheel_style='tuner',
                    headlight_color='#FFFF00',
                    featured=True,
                    views=61
                )
            ]
            for design in sample_designs:
                db.session.add(design)
            db.session.commit()
    
    app.run(debug=True)