import socket
import threading
import pymysql
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import Flask,request,render_template,redirect,session,url_for
from sqlalchemy import create_engine,text
from flask_socketio import SocketIO, send, join_room,emit
app = Flask(__name__)
app.config.from_pyfile('config.py')
socketio = SocketIO(app, manage_session=True)

database=create_engine(app.config['DB_URL'],pool_pre_ping=True ,pool_recycle=3600,echo=True)

def make_key():
    #RSA 공개키 및 개인키 생성
    pr_key = RSA.generate(1024)
    pu_key = pr_key.public_key()
    return pr_key, pu_key

def get_login(user_id):
    
    #:id는 플레이스 홀더역할로 값을 넣을 자리를 표시하는 역할을 한다 
    # 이후.execute({"id":user_id})에서 user_id 	값을 전달하면 실행시,:id가 해당값으로 대체된다

    with database.connect() as conn:
        query = text("SELECT id,passwd FROM PRIVATE WHERE id = :id") 
        #:id는 플레이스 홀더역할로 값을 넣을 자리를 표시하는 역할을 한다 
        # 이후.execute({"id":user_id})에서 user_id 	값을 전달하면 실행시,:id가 해당값으로 대체된다
        result = conn.execute(query, {"id": user_id}).fetchone()
	#user_id="u001"로 입력했다 치면 실행시 :id가 "u001"로 대체된다
	#SQLAlchemy가 '--같은것도 그냥 문자열로만 취급하기때문에 인젝션이 막힌다
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


@app.route('/login', methods=['GET', 'POST'])
def sign_in():
    if 'username' in session:
        return redirect('/')
    if request.method == 'POST':
        user_id = request.form.get("user_id")
        password = request.form.get("password")
        userinfo = get_login(user_id)
        encode_pw = password.encode("utf-8")
        if userinfo:
            encode_ckpw = userinfo["passwd"]
            if bcrypt.checkpw(encode_pw, encode_ckpw):
                session["username"] = user_id
                return redirect('/')
            else:
                result="아이디 혹은 비밀번호가 다릅니다."
                return render_template('login_result.html',result=result)
        else:
            result="아이디 혹은 비밀번호가 다릅니다."
            return render_template('login_result.html',result=result)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/register',methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        user_name=request.form.get("user_name")
        user_id=request.form.get("user_id")
        password=request.form.get("password")
        b_password=bytes(password,"utf-8")
        b_hashed_password=bcrypt.hashpw(password=b_password,salt=bcrypt.gensalt())

        duplication=get_duplication(user_id)
        if duplication:
            result= "사용할 수 없는 아이디입니다." 
            return render_template('register_result.html',result=result)
                    
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
                conn.execute(kquery,{"id":user_id,"passwd":b_hashed_password,"pri_key":pri_str})
                conn.commit()

            result= "회원가입 성공" 
            return render_template('register_result.html',result=result)
        
        except Exception as e:
            print("에러 발생:", e)
            result= "회원가입 실패"
            return render_template('register_result.html',result=result)
    return render_template('register.html')

@app.route('/openchat')        
def open_chat():
    query=text("""SELECT chat FROM ACHAT ORDER BY num ASC""")
    with database.connect() as conn:
        result=conn.execute(query).fetchall()
        chats=[{"chat":row[0]} for row in result]
    return render_template('webchat.html',chats=chats)  # HTML 파일 렌더링
 
@socketio.on('open_message')
def handle_message(msg):
      
    #user_ip=request.remote_addr
    query=text("""INSERT INTO ACHAT(chat) VALUES(:chat)""")
    with database.connect() as conn:
        conn.execute(query,{"chat":msg})
        conn.commit()
    send(msg, broadcast=True)# 모든 클라이언트에게 메시지
    
    




@app.route('/chat',methods=['GET','POST'])
def lobby():
    if request.method=='POST':

        user1=session.get('username')
        user2=request.form.get('user_id')


        # 방 이름을 알파벳순으로 고정해 충돌 방지
        room_users = sorted([user1, user2])
        room_name = f"{room_users[0]}_{room_users[1]}"
        return redirect(url_for('private_chat', room_name=room_name))
    else:
        query=text("""SELECT id FROM USERINFO""")
        with database.connect() as conn:
            #가입된 모든 사용자 목록을 가져오기
            result=conn.execute(query).fetchall()
            users=[]
            for row in result:
                users.append(row[0])
        #가입된 사용자 목록을 users 리스트에 저장

    uname = session.get('username')
    if not uname:
        return render_template('error.html', alert_msg="로그인이 필요합니다")
    return render_template('chat.html',users=users,username=session['username'])

@app.route('/chat/<room_name>')
def private_chat(room_name):
    #  방(room_name) 내부의 기존 암호문 (chat, aes_key)을 모두 가져옴
    query = text("SELECT sender, chat,encrypted_key_for_sender,encrypted_key_for_receiver FROM CHAT WHERE room = :room ORDER BY id ASC")
    with database.connect() as conn:
        result = conn.execute(query, {"room": room_name}).fetchall()
        # chats 리스트에 기존에 저장된 암호문만 넣어둠 (sender, chat, aes_key)
    user = session.get('username')
    chats = []
    for row in result:
        if row[0] == user:          # 내가 보낸 것
            enc_key = row[2]        # encrypted_key_for_sender
        else:                       # 상대방이 보낸 것
            enc_key = row[3]        # encrypted_key_for_receiver
        chats.append({"sender": row[0],
                    "chat":   row[1],
                    "aes_key": enc_key})


    if not user:
        return redirect(url_for('login'))
    # 사용자가 방에 속하지 않으면 접근 금지
    if user not in room_name:
        return redirect(url_for('index'))

    #방 이름(room_name)에서 나(me)와 상대방(other)을 분리
    users = room_name.split("_")
    if users[0] == user:
        other_user = users[1]
    else:
        other_user = users[0]

    #상대방의 공개키(pub_key) 조회
    pub_query = text("SELECT pub_key FROM USERINFO WHERE id = :id")
    with database.connect() as conn:
        pub_result = conn.execute(pub_query, {"id": other_user}).fetchone()
        if not pub_result:
            return "상대방 공개키를 찾을 수 없습니다.", 500
        recipient_pub_key = pub_result[0]  # TEXT 타입(Base64로 인코딩된 PEM 형식)
    #내 공개키(pub_key) 조회
    my_pub_query = text("SELECT pub_key FROM USERINFO WHERE id = :id")
    with database.connect() as conn:
        my_pub_result = conn.execute(my_pub_query, {"id": user}).fetchone()
        if not my_pub_result:
            return "내 공개키를 찾을 수 없습니다.", 500
        my_public_key = my_pub_result[0]
    #내 개인키(pri_key) 조회
    pri_query = text("SELECT pri_key FROM `PRIVATE` WHERE id = :id")
    with database.connect() as conn:
        pri_result = conn.execute(pri_query, {"id": user}).fetchone()
        if not pri_result:
            return "내 개인키를 찾을 수 없습니다.", 500
        my_private_key = pri_result[0]  # TEXT 타입(Base64로 인코딩된 PEM 형식)

    #템플릿에 chats, recipient_pub_key, my_private_key, room, username 변수 전달
    return render_template(
        'private_chat.html',
        room=room_name,
        username=user,
        chats=chats,
        recipient_pub_key=recipient_pub_key,
        my_private_key=my_private_key,
        my_public_key=my_public_key
    )

@socketio.on('join')
def join(room_name):
    username = session.get('username')
    if username in room_name:
        join_room(room_name)
        # 방에 참여

@socketio.on('private_message')
def handle_message(data):
    """
    클라이언트에서 전송된 데이터를 통해:
     - encrypted_message: AES-256-CBC로 암호화된 메시지 문자열 (IV:CipherText 형태)
     - encrypted_key: RSA로 암호화된 AES 대칭키(Base64 문자열)
     - room: 방 이름
     - sender: 보내는 사용자의 ID
    """
    room_name = data.get("room")
    encrypted_message = data.get("encrypted_message")  # 문자열, 예: HEX(IV) + ':' + Base64(ciphertext)
    enc_key_sender   = data.get("key_sender")     # 내가 볼 키
    enc_key_receiver = data.get("key_receiver")   # 상대방이 볼 키
    username = data.get("sender")

    if not all([room_name, encrypted_message, enc_key_sender, enc_key_receiver, username]):
        print("필수 데이터 누락")
        return

    # DB에 암호화된 메시지와 암호화된 AES 키를 함께 저장
    query = text("""
        INSERT INTO CHAT(chat,
                 encrypted_key_for_sender,
                 encrypted_key_for_receiver,
                 room, sender)
    VALUES (:chat, :ks, :kr, :room, :sender)
    """)
    with database.begin() as conn:
        conn.execute(query, {
            "chat": encrypted_message,
            "ks":   enc_key_sender,
            "kr":   enc_key_receiver,
            "room": room_name,
            "sender": username
        })

    #방(room_name)에 속해 있는 모든 클라이언트에게 암호문 그대로 브로드캐스트
    emit('private_message', {
        'sender': username,
        'encrypted_message': encrypted_message,
        'encrypted_key': enc_key_receiver
    }, to=room_name)
    


if __name__ == '__main__':
 
  import ssl
 
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
 
  context.load_cert_chain('/home/fecong/cert.pem', '/home/fecong/key.pem')
 
 
 
  listener = eventlet.listen(('0.0.0.0', 5000))
   
  wrapped_socket = context.wrap_socket(listener, server_side=True)
 
 
 
  eventlet.wsgi.server(wrapped_socket, app)
 