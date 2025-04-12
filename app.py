import socket
import threading
import pymysql
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import Flask,request,render_template
from sqlalchemy import create_engine,text
from flask_socketio import SocketIO, send
app = Flask(__name__)
app.config.from_pyfile('config.py')
socketio = SocketIO(app)

udatabase=create_engine(app.config['UDB_URL'],pool_pre_ping=True ,pool_recycle=3600,echo=True)
kdatabase=create_engine(app.config['KDB_URL'],pool_pre_ping=True,pool_recycle=3600,echo=True)
cdatabase=create_engine(app.config['CDB_URL'],pool_pre_ping=True,pool_recycle=3600,echo=True)


def encrypt_message(message, public_key):
    """메시지를 공개키로 암호화"""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message, private_key):
    """암호화된 메시지를 개인키로 복호화"""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()
def make_key():
    """RSA 공개키 및 개인키 생성"""
    pr_key = RSA.generate(1024)
    pu_key = pr_key.public_key()
    return pr_key, pu_key

def get_login(user_id):
    query = text("SELECT id, passwd FROM PRIVATE WHERE id = :id") 
    #:id는 플레이스 홀더역할로 값을 넣을 자리를 표시하는 역할을 한단다 이후.execute({"id":user_id})에서 user_id 	값을 전달하면 실행시,:id가 해당값으로 대체된다고함

    with kdatabase.connect() as conn:
        result = conn.execute(query, {"id": user_id}).fetchone()
	#user_id="u001"로 입력했다 치면 실행시 :id가 "u001"로 대체된다
	#SQLAlchemy가 '--같은것도 그냥 문자열로만 취급하기때문에 인젝션이 막힌다함
    if result:
        return {"id":result[0],"passwd":result[1]}
    else:
        return
def get_duplication(user_id):
    query = text("SELECT id FROM USERINFO WHERE id = :id")
    with udatabase.connect() as conn:
        result = conn.execute(query, {"id": user_id}).fetchone()
        if result:
            return  {"id":result[0]}
        else:
            return

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login',methods=['POST'])
def sign_in():
    user_id=request.form.get("user_id")
    password=request.form.get("password")
    userinfo=get_login(user_id)
    if userinfo:
        if userinfo["passwd"]==password:
            print("쿠키 설정")#변경할것
        else:
            print("아이디 혹은 비밀번호가 다릅니다.")

    else:
        print("아이디 혹은 비밀번호가 다릅니다.")
@app.route('/register',methods=['POST'])
def sign_up():
    user_name=request.form.get("user_name")
    user_id=request.form.get("user_id")
    password=request.form.get("password")
    duplication=get_duplication(user_id)
    if duplication:
        print("사용할 수 없는 아이디입니다.")
               
    else:
        private_key, public_key = make_key()



@app.route('/openchat')        
def chat():
    return render_template('webchat.html')  # HTML 파일 렌더링
 
@socketio.on('message')
def handle_message(msg):
    print(f"Received message: {msg}")
    send(msg, broadcast=True)  # 모든 클라이언트에게 메시지

    




#@app.route('/chat',method=['POST'])





if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)

#if __name__ == '__main__':
#    app.run(debug=True)
