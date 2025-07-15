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

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

jwt = JWTManager(app)

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

CORS(app, resources={r"/api/*": {"origins": "*"}})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 2. データベースの設計図 (モデル)
# ★★★ ここに user_achievements テーブルの定義を移動 ★★★
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

# 3. フォームの定義
class RegistrationForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired(), EqualTo('pass_confirm', message='パスワードが一致しません。')])
    pass_confirm = PasswordField('パスワード（確認）', validators=[DataRequired()])
    submit = SubmitField('登録する')
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('このユーザー名は既に使用されています。')

class LoginForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    submit = SubmitField('ログイン')

class TransactionForm(FlaskForm):
    date = DateField('日付', format='%Y-%m-%d', default=datetime.utcnow, validators=[DataRequired()])
    category = SelectField('カテゴリー', choices=[('貯金', '貯金'), ('自己投資', '自己投資'), ('金融投資', '金融投資')], validators=[DataRequired()])
    amount = IntegerField('金額（円）', validators=[DataRequired()])
    memo = TextAreaField('メモ')
    submit = SubmitField('記録する')

class TotalAssetsForm(FlaskForm):
    total_assets = IntegerField('現在の総資産額（円）', validators=[DataRequired()])
    submit = SubmitField('更新する')

class ProfileForm(FlaskForm):
    age_range = SelectField('年代', choices=[('未設定', '未設定'), ('20代', '20代'), ('30代', '30代'), ('40代', '40代'), ('50代', '50代'), ('60代以上', '60代以上')])
    income_range = SelectField('年収レンジ', choices=[('未設定', '未設定'), ('-300万', '-300万'), ('300-500万', '300-500万'), ('500-700万', '500-700万'), ('700-1000万', '700-1000万'), ('1000万-', '1000万-')])
    industry = SelectField('業種', choices=[('未設定', '未設定'), ('IT・通信', 'IT・通信'), ('メーカー', 'メーカー'), ('金融', '金融'), ('医療・福祉', '医療・福祉'), ('その他', 'その他')])
    region = SelectField('地域', choices=[('未設定', '未設定'), ('北海道', '北海道'), ('東北', '東北'), ('関東', '関東'), ('中部', '中部'), ('近畿', '近畿'), ('中国・四国', '中国・四国'), ('九州・沖縄', '九州・沖縄')])
    submit_profile = SubmitField('プロフィールを更新する')

# 4. ルーティング (Webページ用)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('登録が完了しました。ログインしてください。','success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('ログインしました。','success')
            return redirect(url_for('dashboard'))
        else:
            flash('ユーザー名またはパスワードが正しくありません。','danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました。','info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    profile_form = ProfileForm(prefix="profile")
    assets_form = TotalAssetsForm(prefix="assets")

    if profile_form.validate_on_submit() and profile_form.submit_profile.data:
        current_user.age_range = profile_form.age_range.data
        current_user.income_range = profile_form.income_range.data
        current_user.industry = profile_form.industry.data
        current_user.region = profile_form.region.data
        db.session.commit()
        flash('プロフィールを更新しました。', 'success')
        return redirect(url_for('profile'))
    
    if assets_form.validate_on_submit() and assets_form.submit.data:
        current_user.total_assets = assets_form.total_assets.data
        asset_record = AssetHistory(amount=assets_form.total_assets.data, user_id=current_user.id)
        db.session.add(asset_record)
        db.session.commit()
        flash('総資産を更新しました。', 'success')
        return redirect(url_for('profile'))

    if request.method == 'GET':
        profile_form.age_range.data = current_user.age_range
        profile_form.income_range.data = current_user.income_range
        profile_form.industry.data = current_user.industry
        profile_form.region.data = current_user.region
        assets_form.total_assets.data = current_user.total_assets
    
    return render_template('profile.html', profile_form=profile_form, assets_form=assets_form)

@app.route('/dashboard')
@login_required
def dashboard():
    form = TransactionForm()
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).limit(10).all()
    return render_template('dashboard_v2.html', form=form, transactions=transactions)

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

# ヘルパー関数
def get_annual_income_from_range(income_range_str):
    if income_range_str == '-300万': return 3000000
    elif income_range_str == '300-500万': return 3000000
    elif income_range_str == '500-700万': return 5000000
    elif income_range_str == '700-1000万': return 7000000
    elif income_range_str == '1000万-': return 10000000
    else: return 0

if __name__ == '__main__':
    app.run(debug=True)
