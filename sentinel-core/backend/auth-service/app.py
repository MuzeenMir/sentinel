"""
SENTINEL Authentication Service

Enterprise-grade authentication and authorization service with JWT tokens,
role-based access control, and security best practices.
"""
import os
import sys
import re
import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import redis
import logging
from enum import Enum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from observability import configure_logging
from metrics import init_metrics
from audit_logger import audit_log, AuditCategory

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": os.environ.get('CORS_ORIGINS', '*').split(',')}})
configure_logging(service_name="auth-service")
init_metrics(app, service_name="auth-service")

# Configuration with secure defaults
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("JWT_SECRET_KEY environment variable is required for production")

app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.environ.get('JWT_ACCESS_EXPIRES_HOURS', '24')))
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=int(os.environ.get('JWT_REFRESH_EXPIRES_DAYS', '30')))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("DATABASE_URL environment variable is required")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
_db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
_is_sqlite = _db_url.startswith('sqlite')
if not _is_sqlite:
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', '10')),
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
else:
    # For SQLite in-memory, use StaticPool so all code shares one connection.
    from sqlalchemy.pool import StaticPool as _StaticPool
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False},
        'poolclass': _StaticPool,
    }
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')

# Initialize extensions
db = SQLAlchemy(app)
jwt_manager = JWTManager(app)

# Redis with connection pooling
redis_pool = redis.ConnectionPool.from_url(
    app.config['REDIS_URL'],
    max_connections=int(os.environ.get('REDIS_MAX_CONNECTIONS', '20'))
)
redis_client = redis.Redis(connection_pool=redis_pool)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=app.config['REDIS_URL']
)

logger = logging.getLogger(__name__)

# Enums
class UserRole(Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    OPERATOR = "operator"
    VIEWER = "viewer"

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
    tenant_id = db.Column(db.BigInteger, nullable=True)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_backup_codes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password: str) -> None:
        """Hash and store password securely."""
        # Validate password strength
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet security requirements")
        # bcrypt returns bytes, decode to store as string
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.password_hash = hashed.decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        if not self.password_hash:
            return False
        # Encode both for comparison
        stored_hash = self.password_hash.encode('utf-8') if isinstance(self.password_hash, str) else self.password_hash
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

    @staticmethod
    def _validate_password_strength(password: str) -> bool:
        """Validate password meets security requirements."""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'status': self.status.value,
            'tenant_id': self.tenant_id,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)

class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(200), unique=True, nullable=False)
    display_name = db.Column(db.String(200))
    status = db.Column(db.String(20), default='active', nullable=False)
    plan = db.Column(db.String(50), default='professional', nullable=False)
    settings = db.Column(db.Text, default='{}')
    data_region = db.Column(db.String(50), default='us-east-1')
    retention_days = db.Column(db.Integer, default=90)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'tenant_id': self.tenant_id,
            'name': self.name,
            'display_name': self.display_name,
            'status': self.status,
            'plan': self.plan,
            'settings': self.settings,
            'data_region': self.data_region,
            'retention_days': self.retention_days,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

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
    try:
        return User.query.get(int(current_user_id))
    except (TypeError, ValueError):
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
@limiter.limit("10 per hour")
def register():
    try:
        data = request.get_json()

        # Validate input
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        # Validate username (alphanumeric, 3-50 chars)
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', data['username']):
            return jsonify({
                'error': 'Username must be 3-50 characters, alphanumeric and underscores only'
            }), 400

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
        
        # Set password with validation
        try:
            user.set_password(data['password'])
        except ValueError as e:
            return jsonify({
                'error': 'Password does not meet security requirements',
                'requirements': [
                    'Minimum 8 characters',
                    'At least one uppercase letter',
                    'At least one lowercase letter',
                    'At least one number',
                    'At least one special character (!@#$%^&*(),.?":{}|<>)'
                ]
            }), 400

        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {user.username}")
        audit_log(AuditCategory.AUTH, "user_registered", actor=f"user:{user.id}",
                  detail={"username": user.username, "role": user.role.value}, redis_client=redis_client)

        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400

        username = data['username']
        password = data['password']

        # Additional IP-based rate limiting
        ip_addr = request.remote_addr
        rate_limit_key = f"login_attempt:{ip_addr}"
        if not rate_limit(rate_limit_key, limit=5, window=300):  # 5 attempts per 5 minutes
            logger.warning(f"Rate limit exceeded for IP: {ip_addr}")
            return jsonify({'error': 'Too many login attempts. Please try again later.'}), 429

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            # Increment failed attempts for both IP and user
            if user:
                increment_failed_login(user)
            redis_client.incr(f"failed_login_ip:{ip_addr}")
            redis_client.expire(f"failed_login_ip:{ip_addr}", 3600)
            audit_log(AuditCategory.AUTH, "login_failed",
                      actor=f"user:{username}", detail={"ip": ip_addr}, redis_client=redis_client)
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if user is locked or inactive
        if user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'Account is inactive or suspended'}), 403
            
        if login_attempts_exceeded(user):
            remaining_time = (user.locked_until - datetime.utcnow()).seconds if user.locked_until else 0
            return jsonify({
                'error': 'Account temporarily locked due to too many failed attempts',
                'retry_after': remaining_time
            }), 403

        # Reset login attempts and update last login
        reset_login_attempts(user)

        # If MFA is enabled, require second factor before issuing full tokens
        if getattr(user, 'mfa_enabled', False) and user.mfa_secret:
            import secrets as _secrets
            mfa_token = _secrets.token_urlsafe(32)
            redis_client.setex(f"mfa_challenge:{mfa_token}", 300, str(user.id))
            return jsonify({
                'mfa_required': True,
                'mfa_token': mfa_token,
                'message': 'MFA verification required',
            }), 200

        # Generate access and refresh tokens with tenant context
        additional_claims = {
            "tenant_id": user.tenant_id,
            "role": user.role.value,
        }
        access_token = create_access_token(
            identity=str(user.id), additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=str(user.id), additional_claims=additional_claims
        )

        logger.info(f"Successful login for user: {user.username} from IP: {ip_addr}")
        audit_log(AuditCategory.AUTH, "login_success", actor=f"user:{user.id}",
                  detail={"username": user.username, "ip": ip_addr}, redis_client=redis_client)

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict(),
            'token_type': 'Bearer',
            'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/v1/auth/mfa/challenge', methods=['POST'])
@limiter.limit("10 per minute")
def mfa_challenge():
    """Complete MFA challenge: exchange mfa_token + TOTP code for full JWT."""
    try:
        import pyotp
        import hashlib
        import json as _json

        data = request.get_json()
        if not data or 'mfa_token' not in data or 'code' not in data:
            return jsonify({'error': 'mfa_token and code required'}), 400

        mfa_token = data['mfa_token']
        code = data['code']

        # Look up pending MFA challenge
        user_id = redis_client.get(f"mfa_challenge:{mfa_token}")
        if not user_id:
            return jsonify({'error': 'Invalid or expired MFA token'}), 401

        user_id = user_id.decode('utf-8') if isinstance(user_id, bytes) else user_id
        user = User.query.get(int(user_id))
        if not user or not user.mfa_secret:
            return jsonify({'error': 'User not found or MFA not configured'}), 401

        # Try TOTP code first
        totp = pyotp.TOTP(user.mfa_secret)
        verified = totp.verify(code, valid_window=1)

        # Try backup codes if TOTP fails
        if not verified and user.mfa_backup_codes:
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            backup_codes = _json.loads(user.mfa_backup_codes)
            if code_hash in backup_codes:
                backup_codes.remove(code_hash)
                user.mfa_backup_codes = _json.dumps(backup_codes)
                verified = True

        if not verified:
            return jsonify({'error': 'Invalid TOTP code'}), 401

        # Consume the challenge token
        redis_client.delete(f"mfa_challenge:{mfa_token}")

        # Issue full JWT tokens
        additional_claims = {
            "tenant_id": user.tenant_id,
            "role": user.role.value,
        }
        access_token = create_access_token(
            identity=str(user.id), additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=str(user.id), additional_claims=additional_claims
        )
        db.session.commit()

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict(),
            'token_type': 'Bearer',
            'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 200

    except Exception as e:
        logger.error(f"MFA challenge error: {str(e)}")
        return jsonify({'error': 'MFA verification failed'}), 500


@app.route('/api/v1/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token."""
    try:
        current_user_id = get_jwt_identity()
        try:
            user = User.query.get(int(current_user_id))
        except (TypeError, ValueError):
            user = User.query.get(current_user_id)
        
        if not user or user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'Invalid or inactive user'}), 401
            
        additional_claims = {
            "tenant_id": user.tenant_id,
            "role": user.role.value,
        }
        access_token = create_access_token(
            identity=current_user_id, additional_claims=additional_claims
        )

        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': int(app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }), 200

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        # Get the JWT's unique identifier (jti) from the token payload
        jwt_payload = get_jwt()
        jti = jwt_payload.get('jti')
        user_id = get_jwt_identity()

        if not jti:
            return jsonify({'error': 'Invalid token'}), 400

        # Blacklist the token
        blacklist_entry = TokenBlacklist(jti=jti)
        db.session.add(blacklist_entry)
        db.session.commit()

        # Also store in Redis for faster lookup
        redis_client.setex(f"token_blacklist:{jti}", 86400, "revoked")

        logger.info(f"User logged out: {user_id}")
        audit_log(AuditCategory.AUTH, "logout", actor=f"user:{user_id}", redis_client=redis_client)

        return jsonify({'message': 'Successfully logged out'}), 200

    except Exception as e:
        db.session.rollback()
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
        audit_log(AuditCategory.CONFIG_CHANGE, "user_updated",
                  detail={"target_user": user.username, "changes": data}, redis_client=redis_client)

        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ── Tenant CRUD (admin only) ───────────────────────────────────────────────

@app.route('/api/v1/tenants', methods=['POST'])
@require_role(UserRole.ADMIN)
def create_tenant():
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Tenant name required'}), 400

        import uuid
        tenant = Tenant(
            tenant_id=str(uuid.uuid4()),
            name=data['name'],
            display_name=data.get('display_name', data['name']),
            plan=data.get('plan', 'professional'),
            data_region=data.get('data_region', 'us-east-1'),
            retention_days=data.get('retention_days', 90),
        )
        db.session.add(tenant)
        db.session.commit()
        logger.info(f"Tenant created: {tenant.name}")
        audit_log(AuditCategory.CONFIG_CHANGE, "tenant_created",
                  detail={"tenant_name": tenant.name, "plan": tenant.plan}, redis_client=redis_client)
        return jsonify({'tenant': tenant.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create tenant error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tenants', methods=['GET'])
@require_role(UserRole.ADMIN)
def list_tenants():
    try:
        tenants = Tenant.query.filter(Tenant.status != 'deactivated').all()
        return jsonify({'tenants': [t.to_dict() for t in tenants]}), 200
    except Exception as e:
        logger.error(f"List tenants error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tenants/<int:tenant_pk>', methods=['GET'])
@require_role(UserRole.ADMIN)
def get_tenant(tenant_pk):
    try:
        tenant = Tenant.query.get_or_404(tenant_pk)
        return jsonify({'tenant': tenant.to_dict()}), 200
    except Exception as e:
        logger.error(f"Get tenant error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tenants/<int:tenant_pk>', methods=['PUT'])
@require_role(UserRole.ADMIN)
def update_tenant(tenant_pk):
    try:
        tenant = Tenant.query.get_or_404(tenant_pk)
        data = request.get_json()
        for field in ('display_name', 'plan', 'data_region', 'retention_days', 'settings'):
            if field in data:
                setattr(tenant, field, data[field])
        db.session.commit()
        return jsonify({'tenant': tenant.to_dict()}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update tenant error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/tenants/<int:tenant_pk>', methods=['DELETE'])
@require_role(UserRole.ADMIN)
def deactivate_tenant(tenant_pk):
    try:
        tenant = Tenant.query.get_or_404(tenant_pk)
        tenant.status = 'deactivated'
        db.session.commit()
        logger.info(f"Tenant deactivated: {tenant.name}")
        audit_log(AuditCategory.CONFIG_CHANGE, "tenant_deactivated",
                  detail={"tenant_name": tenant.name}, redis_client=redis_client)
        return jsonify({'message': 'Tenant deactivated'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Deactivate tenant error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Verify token endpoint
@app.route('/api/v1/auth/verify', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify authentication token and return user info"""
    try:
        current_user_id = get_jwt_identity()
        try:
            user = User.query.get(int(current_user_id))
        except (TypeError, ValueError):
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
    """Create DB tables and initial admin from environment variables if no admin exists."""
    with app.app_context():
        try:
            db.create_all()
            
            if User.query.filter(User.role == UserRole.ADMIN).first() is None:
                # Get admin credentials from environment (required for production)
                uname = os.environ.get('ADMIN_USERNAME')
                email = os.environ.get('ADMIN_EMAIL')
                pwd = os.environ.get('ADMIN_PASSWORD')
                
                if not all([uname, email, pwd]):
                    logger.warning(
                        'ADMIN_USERNAME, ADMIN_EMAIL, and ADMIN_PASSWORD must be set '
                        'to create initial admin user'
                    )
                    return
                
                # Create admin with bypassed password validation for initial setup
                u = User(
                    username=uname,
                    email=email,
                    role=UserRole.ADMIN,
                    status=UserStatus.ACTIVE,
                    password_hash=''
                )
                # Directly set hash for initial admin (bypasses validation)
                hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
                u.password_hash = hashed.decode('utf-8')
                
                db.session.add(u)
                db.session.commit()
                logger.info(f'Created initial admin: {uname}')
                
        except Exception as e:
            db.session.rollback()
            logger.warning(f'Bootstrap initial admin: {e}')


# Token blacklist check callback
@jwt_manager.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if token is in blacklist."""
    jti = jwt_payload.get('jti')
    # Check Redis first (faster); only treat explicit "revoked" marker as blacklisted
    try:
        raw = redis_client.get(f"token_blacklist:{jti}")
        if isinstance(raw, (bytes, str)) and raw in (b"revoked", "revoked"):
            return True
    except Exception:
        pass
    # Fall back to database
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None


# Ensure DB and initial admin (runs on import, e.g. gunicorn)
_bootstrap_initial_admin()

# Register enterprise auth (OIDC, SAML, MFA, SCIM) blueprints
from enterprise_auth import register_enterprise_auth
register_enterprise_auth(app)


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    if debug_mode:
        logger.warning("Running in DEBUG mode - DO NOT use in production!")

    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', '5000')),
        debug=debug_mode
    )
