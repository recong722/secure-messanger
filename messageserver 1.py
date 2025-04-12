from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import Flask,request,make_response
#pip install PyCryptodome 
app = Flask(__name__)
userdata={}
chatdata={}
# 데이터베이스 대신 딕셔너리 사용

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



@app.route('/')
def home():
    return "Welcome to Secure Messenger!"


@app.route('/login',methods=['POST','GET'])
def login():
    user_id = request.form['user_id']
    password = request.form['password']

@app.route('/chat',method=['POST', 'GET'])



if __name__ == '__main__':
    app.run(debug=True)
