from flask import Flask, flash, redirect, render_template, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from datetime import datetime
import os
import sys
import random

WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'

app.config.update(
    MAIL_SERVER='smtp.qq.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USE_TLS=False,
    MAIL_USERNAME='953894443@qq.com',
    MAIL_PASSWORD='hvutpzuxrtwhbffe' # 授权码
)

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True
'''
dev_db = prefix + os.path.join(os.path.dirname(app.root_path), 'data.db')
SECRET_KEY = os.getenv('SECRET_KEY', 'secret string')
SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', dev_db)
SQLALCHEMY_TRACK_MODIFICATIONS = False
'''
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', prefix + os.path.join(app.root_path, 'data.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
mail = Mail(app)


class RegistrationDataBase(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nickname = db.Column(db.String(20))
    password = db.Column(db.String(20))
    email = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.now,index=True)
    timestampUTC = db.Column(db.DateTime, default=datetime.utcnow,index=True)


class VerificationCodeDataBase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50))
    verification = db.Column(db.String(10))


class RegistrationForm(FlaskForm):
    nickname = StringField('Nickname', validators=[DataRequired(), Length(5, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 20)])
    password2 = PasswordField('ConfirmPassword', validators=[DataRequired(), EqualTo("password","Inconsistent password")])

    verificationCode = StringField("VerificationCode", validators=[])
    accept = BooleanField('I accept', validators=[DataRequired()])
    submit1 = SubmitField("Submit")


class GetVerificationCode(FlaskForm):
    email = StringField("EmailAdress", validators=[DataRequired(), Email()])
    submit2 = SubmitField("GetVerificationGode")


class LoginForm(FlaskForm):
    nickname = StringField('Nickname', validators=[DataRequired(), Length(5, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 20)])
    submit = SubmitField("Log in")


class ForgetPwd(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 20)])
    password2 = PasswordField('ConfirmPassword', validators=[DataRequired(), EqualTo("password", "Inconsistent password")])
    verificationCode = StringField("VerificationCode", validators=[])
    submit = SubmitField("Go")


@app.route('/', methods=['Get', 'Post'])
def login():
    form = LoginForm()
    if form.submit.data:
        pwd = get_pwd(form.nickname.data)
        nick = form.nickname.data
        #if pwd == form.password.data:
        if check_password_hash(pwd, form.password.data):
            session[nick] = True
            return redirect(url_for("index", nick=nick))
        else:
            return "密码不正确"
    return render_template("login.html", form1=form)


@app.route('/registration', methods=['Get', 'Post'])
def registration():
    form1 = RegistrationForm()
    form2 = GetVerificationCode()

    nickname = form1.nickname.data
    password = form1.password2.data
    email = form2.email.data
    code = random.randint(100000, 999999)

    if form2.submit2.data and form2.validate():
        if find_email(email):
            save_verification(email=email, code=code)
            info = "Your verification code is" + str(code) + ".Please keeping properly!"
            send_message("Your verification code", str(email), "953894443@qq.com", info)
        else:
            return "该邮箱已被注册"

    if form1.submit1.data:
        ver = get_verification(form2.email.data)

        if ver == form1.verificationCode.data:
            password = generate_password_hash(password)
            message = RegistrationDataBase(nickname=nickname, password=password, email=email)
            db.session.add(message)
            db.session.commit()
            flash("Registered successfully")

            body = str(nickname)+",welcomne !"
            send_message("Welcome !", str(email), "953894443@qq.com", body)
            return redirect(url_for("login"))
        else:
            return "验证码不正确"

    messages = RegistrationDataBase.query.order_by(RegistrationDataBase.timestampUTC.desc()).all()
    return render_template("registration.html", form1=form1, form2=form2, messages=messages)


@app.route('/index/<nick>', methods=['Get', 'Post'])
def index(nick):
    if nick not in session:
        return "未登录"
    return render_template("index.html", nick=nick)


@app.route('/logout/<nick>',methods=['GET','POST'])
def logout(nick):
    if nick in session:
        session.pop(nick)
    return redirect(url_for("index", nick=nick))


@app.route('/forgetpassword', methods=['Get', 'Post'])
def forget_pwd():
    form1 = ForgetPwd()
    form2 = GetVerificationCode()

    email = form2.email.data
    code = random.randint(100000, 999999)

    if form2.submit2.data:
        if find_email(email):
            return "该邮箱未被注册过"
        else:
            save_verification(email=email, code=code)
            info = "Your verification code is" + str(code) + ".Please keeping properly!"
            send_message("Your verification code", str(email), "953894443@qq.com", info)
            #return "验证码已发往邮箱，请查收"

    if form1.submit.data:
        ma = get_verification(email)
        if str(ma) == str(form1.verificationCode.data):
            password = form1.password2.data
            reset_pwd(data=email, password=password)

            nickname = get_nickname(email)
            body = str(nickname) + ",welcomne !"
            send_message("Welcome !", str(email), "953894443@qq.com", body)
            return "密码修改成功!"
        else:
            return "验证码不正确!"

    return render_template("forgetPwd.html", form1=form1, form2=form2)


@app.route('/rules', methods=['Get', 'Post'])
def rules():
    return render_template("rules.html")


def find_email(email):
    add = RegistrationDataBase.query.filter(RegistrationDataBase.email == email).all()
    if add:
        return False
    else:
        return True


def reset_pwd(data, password):
    id = RegistrationDataBase.query.filter(VerificationCodeDataBase.email == data).all()
    id.reverse()
    id = id[0].id
    user = RegistrationDataBase.query.get(id)
    user.password = generate_password_hash(password)
    db.session.commit()


def get_nickname(data):
    nick = RegistrationDataBase.query.filter(RegistrationDataBase.email == data).all()
    nick.reverse()
    return nick[0].nickname


def get_pwd(data):
    pwd = RegistrationDataBase.query.filter(RegistrationDataBase.nickname == data).all()
    pwd.reverse()
    return pwd[0].password


def save_verification(email, code):
    message = VerificationCodeDataBase(email=email, verification=code)
    db.session.add(message)
    db.session.commit()


def get_verification(data):
    code = VerificationCodeDataBase.query.filter(VerificationCodeDataBase.email == data).all()
    code.reverse()
    '''
    for i in code:
        print(i.verification)
    '''
    return code[0].verification


def send_message(subject, recipients, sender, body):
    msg = Message(subject=subject, recipients=[recipients], sender=sender, body=body)
    mail.send(msg)


if __name__ == '__main__':
    app.run()
