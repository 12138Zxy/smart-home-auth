from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, 
    jwt_required, 
    get_jwt_identity
)
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from app import db, mail
from app.auth.models import User
from app.auth.security import (
    record_login_attempt, 
    check_suspicious_login,
    generate_captcha
)
from flask_mail import Message
from config import Config

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Username already exists"}), 400
    
    user = User(
        username=data['username'],
        email=data['email']
    )
    user.password = data['password']
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"msg": "User created successfully"}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    # 记录登录尝试
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    if not user or not user.verify_password(data['password']):
        record_login_attempt(user.id if user else None, ip_address, user_agent, 'failed')
        
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                user.locked = True
                user.locked_until = datetime.utcnow() + Config.LOCK_TIME
                send_security_alert(user, ip_address)
            db.session.commit()
        
        return jsonify({"msg": "Invalid username or password"}), 401
    
    # 检查账户是否被锁定
    if user.is_locked():
        return jsonify({
            "msg": "Account locked due to multiple failed attempts",
            "unlock_time": user.locked_until.isoformat()
        }), 403
    
    # 检查可疑登录
    if check_suspicious_login(user, ip_address):
        send_security_alert(user, ip_address)
        return jsonify({
            "msg": "Suspicious login detected. Please verify your identity.",
            "captcha_required": True,
            "captcha": generate_captcha()
        }), 403
    
    # 重置失败尝试计数
    user.failed_attempts = 0
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # 记录成功登录
    record_login_attempt(user.id, ip_address, user_agent, 'success')
    
    # 创建访问令牌
    access_token = create_access_token(identity=user.id)
    return jsonify({
        "access_token": access_token,
        "user_id": user.id,
        "role": user.role
    }), 200

def send_security_alert(user, ip_address):
    try:
        msg = Message(
            "安全警报：异常登录活动检测",
            recipients=[user.email]
        )
        msg.html = f"""
        <h3>您的账户 {user.username} 检测到异常活动</h3>
        <p>登录尝试来自IP地址: {ip_address}</p>
        <p>时间: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p>如果这不是您的操作，请立即更改密码。</p>
        """
        mail.send(msg)
    except Exception as e:
        print(f"Error sending security email: {e}")

@bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200