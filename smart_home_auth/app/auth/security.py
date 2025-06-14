import geoip2.database
from flask import request
from flask_jwt_extended import get_jwt_identity
from app.auth.models import User, LoginHistory
from datetime import datetime, timedelta
from app import db

# 初始化GeoIP2读取器
geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def record_login_attempt(user_id, ip_address, user_agent, status):
    try:
        location = ""
        if ip_address != '127.0.0.1':
            response = geoip_reader.city(ip_address)
            location = f"{response.country.name}, {response.city.name}"
        
        login_record = LoginHistory(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            location=location
        )
        db.session.add(login_record)
        db.session.commit()
    except Exception as e:
        print(f"Error recording login attempt: {e}")

def check_suspicious_login(user, ip_address):
    # 检查海外IP
    if ip_address != '127.0.0.1':
        try:
            response = geoip_reader.city(ip_address)
            if response.country.iso_code != 'CN':  # 假设主要用户在中国
                return True
        except:
            pass
    
    # 检查异常时间登录
    now = datetime.utcnow()
    if 0 <= now.hour < 6:  # 凌晨登录
        return True
    
    return False

def generate_captcha():
    # 实现图形验证码生成逻辑
    pass