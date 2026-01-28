import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
import redis
import logging
from enum import Enum

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://sentinel:password@localhost/sentinel_auth')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Initialize extensions
db = SQLAlchemy(app)
jwt_manager = JWTManager(app)
redis_client = redis.from_url(app.config['REDIS_URL'])

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enums
class UserRole(Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"

class UserStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    status = db.Column(db.Enum(UserStatus), default=UserStatus.ACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)

# Utility Functions
def require_role(required_role):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user = get_current_user()
            if current_user.role != required_role:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    current_user_id = get_jwt_identity()
    return User.query.get(current_user_id)

def rate_limit(key, limit=10, window=60):
    """Simple rate limiting using Redis"""
    current = redis_client.get(key)
    if current is not None:
        current = int(current)
        if current >= limit:
            return False
        redis_client.incr(key)
        redis_client.expire(key, window)
    else:
        redis_client.setex(key, window, 1)
    return True

def login_attempts_exceeded(user):
    """Check if user has exceeded login attempts"""
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return user.failed_login_attempts >= 5

def increment_failed_login(user):
    """Increment failed login attempts"""
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= 5:
        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

def reset_login_attempts(user):
    """Reset failed login attempts after successful login"""
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()

# Routes
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        # Validate input
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field}'}), 400

        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == data['username']) | (User.email == data['email'])
        ).first()

        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 409

        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            role=getattr(UserRole, data['role'].upper(), UserRole.SECURITY_ANALYST),
            status=UserStatus.ACTIVE
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {user.username}")

        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400

        username = data['username']
        password = data['password']

        # Rate limiting
        ip_addr = request.remote_addr
        rate_limit_key = f"login_attempt:{ip_addr}"
        if not rate_limit(rate_limit_key, limit=5, window=300):  # 5 attempts per 5 minutes
            return jsonify({'error': 'Too many login attempts'}), 429

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            # Increment failed attempts for both IP and user
            increment_failed_login(user) if user else None
            redis_client.incr(f"failed_login_ip:{ip_addr}")
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if user is locked or inactive
        if user.status != UserStatus.ACTIVE or login_attempts_exceeded(user):
            return jsonify({'error': 'Account locked or inactive'}), 403

        # Reset login attempts and update last login
        reset_login_attempts(user)

        # Generate access token
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(hours=24)
        )

        logger.info(f"Successful login for user: {user.username}")

        return jsonify({
            'access_token': access_token,
            'user': user.to_dict(),
            'expires_in': 86400  # 24 hours in seconds
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt_identity()

        # Blacklist the token
        blacklist_entry = TokenBlacklist(jti=jti)
        db.session.add(blacklist_entry)
        db.session.commit()

        logger.info(f"User logged out: {get_jwt_identity()}")

        return jsonify({'message': 'Successfully logged out'}), 200

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    try:
        user = get_current_user()
        data = request.get_json()

        if not data or 'current_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Current and new password required'}), 400

        if not user.check_password(data['current_password']):
            return jsonify({'error': 'Current password incorrect'}), 401

        user.set_password(data['new_password'])
        db.session.commit()

        logger.info(f"Password changed for user: {user.username}")

        return jsonify({'message': 'Password updated successfully'}), 200

    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/users', methods=['GET'])
@require_role(UserRole.ADMIN)
def get_users():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        role_filter = request.args.get('role')

        query = User.query

        if role_filter:
            query = query.filter(User.role == getattr(UserRole, role_filter.upper()))

        users = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'users': [user.to_dict() for user in users.items],
            'total': users.total,
            'pages': users.pages,
            'current_page': page
        }), 200

    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/users/<int:user_id>', methods=['PUT'])
@require_role(UserRole.ADMIN)
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()

        if 'role' in data:
            user.role = getattr(UserRole, data['role'].upper())
        if 'status' in data:
            user.status = getattr(UserStatus, data['status'].upper())

        db.session.commit()

        logger.info(f"User updated by admin: {get_current_user().username} updated {user.username}")

        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Verify token endpoint
@app.route('/api/v1/auth/verify', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify authentication token and return user info"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'Invalid or inactive user'}), 401
            
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({'error': 'Token verification failed'}), 500

# Error handlers
@jwt_manager.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt_manager.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt_manager.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token required'}), 401

@jwt_manager.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked'}), 401

def _bootstrap_initial_admin():
    """Create DB tables and initial admin from ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL if no admin exists."""
    with app.app_context():
        try:
            db.create_all()
            if User.query.filter(User.role == UserRole.ADMIN).first() is None:
                uname = os.environ.get('ADMIN_USERNAME', 'Santa')
                email = os.environ.get('ADMIN_EMAIL', 'santa@sentinel.local')
                pwd = os.environ.get('ADMIN_PASSWORD', 'Ggxr@123')
                u = User(username=uname, email=email, role=UserRole.ADMIN, status=UserStatus.ACTIVE, password_hash='')
                u.set_password(pwd)
                db.session.add(u)
                db.session.commit()
                logger.info(f'Created initial admin: {uname}')
        except Exception as e:
            db.session.rollback()
            logger.warning(f'Bootstrap initial admin: {e}')


# Ensure DB and initial admin (runs on import, e.g. gunicorn)
_bootstrap_initial_admin()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('FLASK_DEBUG', False))
