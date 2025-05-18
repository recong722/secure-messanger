import socket
import threading
import pymysql
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import Flask,request,render_template,redirect,session,url_for
from sqlalchemy import create_engine,text
from flask_socketio import SocketIO, send, emit
app = Flask(__name__)
app.config.from_pyfile('config.py')
socketio = SocketIO(app)

database=create_engine(app.config['DB_URL'],pool_pre_ping=True ,pool_recycle=3600,echo=True)
connected_users = {}


def encrypt_message(message, public_key):
    #메시지를 공개키로 암호화
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message, private_key):
    #암호화된 메시지를 개인키로 복호화
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()
def make_key():
    #RSA 공개키 및 개인키 생성
    pr_key = RSA.generate(1024)
    pu_key = pr_key.public_key()
    return pr_key, pu_key

def get_login(user_id):
    
    #:id는 플레이스 홀더역할로 값을 넣을 자리를 표시하는 역할을 한단다 
    # 이후.execute({"id":user_id})에서 user_id 	값을 전달하면 실행시,:id가 해당값으로 대체된다고함

    with database.connect() as conn:
        query = text("SELECT id,passwd FROM PRIVATE WHERE id = :id") 
        #:id는 플레이스 홀더역할로 값을 넣을 자리를 표시하는 역할을 한단다 
        # 이후.execute({"id":user_id})에서 user_id 	값을 전달하면 실행시,:id가 해당값으로 대체된다고함
        result = conn.execute(query, {"id": user_id}).fetchone()
	#user_id="u001"로 입력했다 치면 실행시 :id가 "u001"로 대체된다
	#SQLAlchemy가 '--같은것도 그냥 문자열로만 취급하기때문에 인젝션이 막힌다함
    if result:
        return {"id":result[0],"passwd":result[1]}
    else:
        return
def get_duplication(user_id):
    query = text("SELECT id FROM USERINFO WHERE id = :id")
    with database.connect() as conn:
        result = conn.execute(query, {"id": user_id}).fetchone()
        if result:
            return  {"id":result[0]}
        else:
            return

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login',methods=['GET','POST'])
def sign_in():
    if 'username' in session:
     return redirect('/')
    if request.method =='POST':
        user_id=request.form.get("user_id")
        password=request.form.get("password")
        userinfo=get_login(user_id)
        if userinfo:
            if userinfo["passwd"]==password:
                session["username"]=user_id #변경할것
                return redirect('/')
            else:
                return "아이디 혹은 비밀번호가 다릅니다."

        else:
            return "아이디 혹은 비밀번호가 다릅니다."
    return render_template('login.html')

@app.route('/register',methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        user_name=request.form.get("user_name")
        user_id=request.form.get("user_id")
        password=request.form.get("password")
        duplication=get_duplication(user_id)
        if duplication:
            return "사용할 수 없는 아이디입니다."
                    
        private_key, public_key = make_key()
        pri_str = private_key.export_key().decode()
        pub_str = public_key.export_key().decode()

        try:
            uquery=text("""INSERT INTO USERINFO(name,id,pub_key) VALUES (:name,:id,:pub_key)""")
            with database.connect() as conn:
                conn.execute(uquery,{"name":user_name,"id":user_id,"pub_key":pub_str})
                conn.commit()
            kquery=text("""INSERT INTO PRIVATE(id,passwd,pri_key) VALUES (:id,:passwd,:pri_key)""")
            with database.connect() as conn:
                conn.execute(kquery,{"id":user_id,"passwd":password,"pri_key":pri_str})
                conn.commit()

            return "회원가입 성공" 
        
        except Exception as e:
            print("에러 발생:", e)
            return "회원가입 실패"
    return render_template('register.html')

@app.route('/openchat')        
def chat():
    query=text("""SELECT chat FROM ACHAT ORDER BY num ASC""")
    with database.connect() as conn:
        result=conn.execute(query).fetchall()
        chats=[{"chat":row[0]} for row in result]
    return render_template('webchat.html',chats=chats)  # HTML 파일 렌더링
 
@socketio.on('message')
def handle_message(msg):
      
    user_ip=request.remote_addr
    print(f"[{user_ip}] 메세지 수신:{msg}")
    query=text("""INSERT INTO ACHAT(chat) VALUES(:chat)""")
    with database.connect() as conn:
        conn.execute(query,{"chat":msg})
        conn.commit()
    send(msg, broadcast=True)# 모든 클라이언트에게 메시지
    
    




@app.route('/chat',methods=['POST'])
def chat():
    user1=session.get('user_id')
    user2=request.form.get('user_id')
    if not user1 or not user2:
        return "존재하지 않는 사용자이거나 접속 중이 아닙니다.", 400

    # 방 이름을 알파벳순으로 고정해 충돌 방지
    room_users = sorted([user1, user2])
    room_name = f"{room_users[0]}_{room_users[1]}"

    # 해당 1:1 채팅방으로 리디렉션
    return redirect(url_for('private_chat', room_name=room_name))

@app.route('/chat/<room_name>')
def private_chat(room_name):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('private_chat.html', room=room_name, username=session['username'])
@socketio.on('message')
def handle_message(msg):
      

    query=text("""INSERT INTO ACHAT(chat) VALUES(:chat)""")
    with database.connect() as conn:
        conn.execute(query,{"chat":msg})
        conn.commit()
    emit
    
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)


#if __name__ == '__main__':
#    app.run(debug=True)
