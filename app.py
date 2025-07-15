import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, DateField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import func, extract
import json
from flasgger import Swagger
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
# ★★★ 新しくインポート ★★★
from flask_cors import CORS

# 1. アプリケーションの初期設定
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key') 

if os.getenv('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("postgres://", "postgresql://", 1)
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

# Webページ用のログインマネージャー
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# JWTマネージャーの初期化
jwt = JWTManager(app)

# Swagger (API仕様書) の設定
template = {
    "swagger": "2.0",
    "info": {
        "title": "Portfolio Arena API",
        "description": "API for Portfolio Arena",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "bearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Access Token (e.g. 'Bearer <token>')"
        }
    }
}
swagger = Swagger(app, template=template)

# ★★★ CORSの設定を追加 ★★★
# これにより、/api/ から始まるURLへの外部からのアクセスが許可されます
CORS(app, resources={r"/api/*": {"origins": "*"}})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 2. データベースの設計図 (モデル)
# (変更なし)
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    age_range = db.Column(db.String(64), default='未設定')
    income_range = db.Column(db.String(64), default='未設定')
    industry = db.Column(db.String(64), default='未設定')
    region = db.Column(db.String(64), default='未設定')
    total_assets = db.Column(db.Integer, default=0)
    transactions = db.relationship('Transaction', backref='user', lazy='dynamic')
    asset_history = db.relationship('AssetHistory', backref='user', lazy='dynamic')
    achievements = db.relationship('Achievement', secondary=user_achievements,
                                   backref=db.backref('users', lazy='dynamic'))
    
    def __init__(self, username, password):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(64), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    memo = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class AssetHistory(db.Model):
    __tablename__ = 'asset_history'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    amount = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

user_achievements = db.Table('user_achievements',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('achievement_id', db.Integer, db.ForeignKey('achievements.id'))
)

class Achievement(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.String(256))
    icon = db.Column(db.String(128))

# 3. フォームの定義 (変更なし)
# ... (省略) ...

# 4. ルーティング (Webページ用) (変更なし)
# ... (省略) ...

# 5. APIエンドポイント
@app.route('/api/v1/login', methods=['POST'])
def api_login():
    """
    ユーザーを認証し、アクセストークンを発行する
    ---
    tags: [Auth]
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required: [username, password]
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Success
      401:
        description: Unauthorized
    """
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user and user.check_password(data.get('password')):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)

    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/api/v1/summary')
@jwt_required()
def api_summary():
    """
    ログインユーザーのダッシュボードサマリー情報を取得する
    ---
    tags: [Summary]
    security:
      - bearerAuth: []
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    response_data = {
        'username': user.username,
        'total_assets': user.total_assets,
    }
    return jsonify(response_data)

@app.route('/api/v1/transactions', methods=['GET', 'POST'])
@jwt_required()
def api_transactions():
    """
    ユーザーの投資記録を取得、または新規作成する
    ---
    tags: [Transactions]
    security:
      - bearerAuth: []
    """
    user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json()
        new_transaction = Transaction(
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            category=data['category'],
            amount=data['amount'],
            memo=data.get('memo', ''),
            user_id=user_id
        )
        db.session.add(new_transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction created!', 'id': new_transaction.id}), 201

    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()
    output = []
    for tx in transactions:
        output.append({
            'id': tx.id,
            'date': tx.date.strftime('%Y-%m-%d'),
            'category': tx.category,
            'amount': tx.amount,
            'memo': tx.memo
        })
    return jsonify({'transactions': output})

# (ヘルパー関数などは省略)
# ...

if __name__ == '__main__':
    app.run(debug=True)
