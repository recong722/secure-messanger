dbs = {
    'host': '데이터베이스 IP',
        #데이터베이스 IP
        'user': 'recong',
        #외부 혹은 로컬로 연결할수있는 계정
        'password': 'recong',
        #그 계정 비밀번호
        'database': 'project',
        #데이터베이스 이름
        'port': '3306'
        #포트

}


DB_URL = f"mysql+pymysql://{dbs['user']}:{dbs['password']}@{dbs['host']}:{dbs['port']}/{dbs['database']}?charset=utf8mb4"
#SQLAlchemy에서 MySQL에 연결할 때 사용되는 URL을 생성
SECRET_KEY = 'CipherCiphertahc'
#비밀키


#데이터베이스 설정을 따로 관리하는 파일 config.py
