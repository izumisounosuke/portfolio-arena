import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy import func
import json

# 1. アプリケーションの初期設定
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# ★★★ ここからが本番環境と開発環境を切り替えるための修正です ★★★
# Renderの環境変数にDATABASE_URLがあればそれを使い、なければSQLiteを使う
if os.getenv('DATABASE_URL'):
    # RenderのPostgreSQL URLは 'postgres://' で始まるため、SQLAlchemyが認識できるように 'postgresql://' に置換します
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("postgres://", "postgresql://", 1)
else:
    # 開発環境（あなたのPC）では、これまで通り 'data.sqlite' を使います
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
# ★★★ ここまでが修正箇所です ★★★

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 2. データベースの設計図 (モデル)
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
    investments = db.relationship('Investment', backref='user', lazy='dynamic')
    achievements = db.relationship('Achievement', secondary=user_achievements,
                                   backref=db.backref('users', lazy='dynamic'))
    
    def __init__(self, username, password):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Investment(db.Model):
    __tablename__ = 'investments'
    id = db.Column(db.Integer, primary_key=True)
    year_month = db.Column(db.String(7), nullable=False)
    income = db.Column(db.Integer, nullable=False)
    saving = db.Column(db.Integer, nullable=False)
    self_investment = db.Column(db.Integer, nullable=False)
    financial_investment = db.Column(db.Integer, nullable=False)
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

class InvestmentForm(FlaskForm):
    year_month = StringField('年月 (例: 2025-07)', validators=[DataRequired()])
    income = IntegerField('手取り月収（円）', validators=[DataRequired()])
    saving = IntegerField('貯金額（円）', default=0, validators=[DataRequired()])
    self_investment = IntegerField('自己投資額（円）', default=0, validators=[DataRequired()])
    financial_investment = IntegerField('金融投資額（円）', default=0, validators=[DataRequired()])
    submit = SubmitField('この内容で記録する')

class ProfileForm(FlaskForm):
    age_range = SelectField('年代', choices=[('未設定', '未設定'), ('20代', '20代'), ('30代', '30代'), ('40代', '40代'), ('50代', '50代'), ('60代以上', '60代以上')])
    income_range = SelectField('年収レンジ', choices=[('未設定', '未設定'), ('-300万', '-300万'), ('300-500万', '300-500万'), ('500-700万', '500-700万'), ('700-1000万', '700-1000万'), ('1000万-', '1000万-')])
    industry = SelectField('業種', choices=[('未設定', '未設定'), ('IT・通信', 'IT・通信'), ('メーカー', 'メーカー'), ('金融', '金融'), ('医療・福祉', '医療・福祉'), ('その他', 'その他')])
    region = SelectField('地域', choices=[('未設定', '未設定'), ('北海道', '北海道'), ('東北', '東北'), ('関東', '関東'), ('中部', '中部'), ('近畿', '近畿'), ('中国・四国', '中国・四国'), ('九州・沖縄', '九州・沖縄')])
    submit = SubmitField('プロフィールを更新する')

# 4. ルーティング
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
        check_achievements(user)
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
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.age_range = form.age_range.data
        current_user.income_range = form.income_range.data
        current_user.industry = form.industry.data
        current_user.region = form.region.data
        db.session.commit()
        flash('プロフィールを更新しました。', 'success')
        return redirect(url_for('profile'))
    
    form.age_range.data = current_user.age_range
    form.income_range.data = current_user.income_range
    form.industry.data = current_user.industry
    form.region.data = current_user.region
    
    user_achievements = current_user.achievements
    
    return render_template('profile.html', form=form, achievements=user_achievements)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = InvestmentForm()
    
    if form.validate_on_submit():
        existing_investment = Investment.query.filter_by(user_id=current_user.id, year_month=form.year_month.data).first()
        if existing_investment:
            existing_investment.income = form.income.data
            existing_investment.saving = form.saving.data
            existing_investment.self_investment = form.self_investment.data
            existing_investment.financial_investment = form.financial_investment.data
        else:
            investment = Investment(year_month=form.year_month.data,
                                    income=form.income.data,
                                    saving=form.saving.data,
                                    self_investment=form.self_investment.data,
                                    financial_investment=form.financial_investment.data,
                                    user_id=current_user.id)
            db.session.add(investment)
        db.session.commit()
        check_achievements(current_user)
        flash(f"{form.year_month.data}の活動を記録しました！",'success')
        return redirect(url_for('dashboard'))

    filters = {
        'age': request.args.get('age_filter', 'all'),
        'income': request.args.get('income_filter', 'all'),
        'industry': request.args.get('industry_filter', 'all')
    }
    latest_investment = Investment.query.filter_by(user_id=current_user.id).order_by(Investment.year_month.desc()).first()
    scores = {'total_fir': 0, 'saving_fir': 0, 'self_investment_fir': 0, 'financial_investment_fir': 0}
    if latest_investment and latest_investment.income > 0:
        total_investment = latest_investment.saving + latest_investment.self_investment + latest_investment.financial_investment
        income = latest_investment.income
        scores['total_fir'] = (total_investment / income) * 100
        scores['saving_fir'] = (latest_investment.saving / income) * 100
        scores['self_investment_fir'] = (latest_investment.self_investment / income) * 100
        scores['financial_investment_fir'] = (latest_investment.financial_investment / income) * 100
    
    percentiles = calculate_percentiles(current_user, latest_investment, scores, filters)
    
    investments = Investment.query.filter_by(user_id=current_user.id).order_by(Investment.year_month.asc()).all()

    chart_data = {
        'labels': json.dumps([inv.year_month for inv in investments]),
        'saving_data': [inv.saving for inv in investments],
        'self_investment_data': [inv.self_investment for inv in investments],
        'financial_investment_data': [inv.financial_investment for inv in investments],
    }
    
    display_investments = investments[::-1]

    return render_template('dashboard.html', form=form, scores=scores, percentiles=percentiles, latest_investment=latest_investment, investments=display_investments, filters=filters, chart_data=chart_data)

def calculate_percentiles(target_user, target_investment, scores, filters):
    percentiles = {'total': 100, 'saving': 100, 'self_investment': 100, 'financial_investment': 100}
    if not target_investment:
        return percentiles
    latest_month = target_investment.year_month
    query = Investment.query.join(User).filter(Investment.year_month == latest_month)
    if filters['age'] != 'all':
        query = query.filter(User.age_range == filters['age'])
    if filters['income'] != 'all':
        query = query.filter(User.income_range == filters['income'])
    if filters['industry'] != 'all':
        query = query.filter(User.industry == filters['industry'])
    all_investments_in_group = query.all()
    all_scores = []
    for inv in all_investments_in_group:
        if inv.income > 0:
            total_inv = inv.saving + inv.self_investment + inv.financial_investment
            score = {
                'total': (total_inv / inv.income) * 100,
                'saving': (inv.saving / inv.income) * 100,
                'self_investment': (inv.self_investment / inv.income) * 100,
                'financial_investment': (inv.financial_investment / inv.income) * 100
            }
            all_scores.append(score)
    total_users = len(all_scores)
    if total_users == 0:
        return percentiles
    my_score = {
        'total': scores.get('total_fir', 0),
        'saving': scores.get('saving_fir', 0),
        'self_investment': scores.get('self_investment_fir', 0),
        'financial_investment': scores.get('financial_investment_fir', 0)
    }
    for category in ['total', 'saving', 'self_investment', 'financial_investment']:
        higher_rank_count = sum(1 for score in all_scores if score[category] > my_score[category])
        percentiles[category] = (higher_rank_count / total_users) * 100 if total_users > 0 else 100
    return percentiles

ACHIEVEMENTS = {
    'first_step': {'name': '最初の一歩', 'description': 'アリーナへようこそ！最初のユーザーとして登録されました。'},
    'first_record': {'name': '記録の始まり', 'description': '初めて月次データを記録しました。'},
    'saving_guardian_bronze': {'name': '貯蓄の守り手（銅）', 'description': '貯金部門で上位50%以内を達成しました。'},
    'saving_guardian_silver': {'name': '貯蓄の守り手（銀）', 'description': '貯金部門で上位25%以内を達成しました。'},
    'saving_guardian_gold': {'name': '貯蓄の守り手（金）', 'description': '貯金部門で上位10%以内を達成しました。'},
}

def check_achievements(user):
    with app.app_context():
        for key, value in ACHIEVEMENTS.items():
            if not Achievement.query.filter_by(name=value['name']).first():
                ach = Achievement(name=value['name'], description=value['description'], icon=f"{key}.png")
                db.session.add(ach)
        db.session.commit()
        earned_ach_names = [ach.name for ach in user.achievements]
        if ACHIEVEMENTS['first_step']['name'] not in earned_ach_names:
            ach = Achievement.query.filter_by(name=ACHIEVEMENTS['first_step']['name']).first()
            user.achievements.append(ach)
            flash(f"称号『{ach.name}』を獲得しました！", 'info')
        if user.investments.count() > 0 and ACHIEVEMENTS['first_record']['name'] not in earned_ach_names:
            ach = Achievement.query.filter_by(name=ACHIEVEMENTS['first_record']['name']).first()
            user.achievements.append(ach)
            flash(f"称号『{ach.name}』を獲得しました！", 'info')
        latest_investment = user.investments.order_by(Investment.year_month.desc()).first()
        if latest_investment:
            scores = {'total_fir': 0, 'saving_fir': 0, 'self_investment_fir': 0, 'financial_investment_fir': 0}
            if latest_investment.income > 0:
                scores['saving_fir'] = (latest_investment.saving / latest_investment.income) * 100
            percentiles = calculate_percentiles(user, latest_investment, scores, {'age': 'all', 'income': 'all', 'industry': 'all'})
            if percentiles['saving'] <= 10 and ACHIEVEMENTS['saving_guardian_gold']['name'] not in earned_ach_names:
                ach = Achievement.query.filter_by(name=ACHIEVEMENTS['saving_guardian_gold']['name']).first()
                user.achievements.append(ach)
                flash(f"称号『{ach.name}』を獲得しました！", 'info')
            elif percentiles['saving'] <= 25 and ACHIEVEMENTS['saving_guardian_silver']['name'] not in earned_ach_names:
                ach = Achievement.query.filter_by(name=ACHIEVEMENTS['saving_guardian_silver']['name']).first()
                user.achievements.append(ach)
                flash(f"称号『{ach.name}』を獲得しました！", 'info')
            elif percentiles['saving'] <= 50 and ACHIEVEMENTS['saving_guardian_bronze']['name'] not in earned_ach_names:
                ach = Achievement.query.filter_by(name=ACHIEVEMENTS['saving_guardian_bronze']['name']).first()
                user.achievements.append(ach)
                flash(f"称号『{ach.name}』を獲得しました！", 'info')
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
