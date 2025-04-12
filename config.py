dbs = {
    'userdb': {
        'host': 'ip주소',
        'user': '계정id',
        'password': '계정비밀번호',
        'database': 'USERINFO',
        'port': '3306'
    },
    'keydb': {
        'host': 'ip주소',
        'user': '계정id',
        'password': '계정비밀번호',
        'database': 'PRIVATE',
        'port': '3306'
    },
    'chatdb':{
 	'host': 'ip주소',
        'user': '계정id',
        'password': '계정비밀번호',
        'database': 'CHAT',
        'port': '3306'
}
}


UDB_URL = f"mysql+pymysql://{dbs['userdb']['user']}:{dbs['userdb']['password']}@{dbs['userdb']['host']}:{dbs['userdb']['port']}/{dbs['userdb']['database']}?charset=utf8mb4"
KDB_URL = f"mysql+pymysql://{dbs['keydb']['user']}:{dbs['keydb']['password']}@{dbs['keydb']['host']}:{dbs['keydb']['port']}/{dbs['keydb']['database']}?charset=utf8mb4"
CDB_URL = f"mysql+pymysql://{dbs['chatdb']['user']}:{dbs['chatdb']['password']}@{dbs['chatdb']['host']}:{dbs['chatdb']['port']}/{dbs['chatdb']['database']}?charset=utf8mb4"
#SQLAlchemy에서 MySQL에 연결할 때 사용되는 URL을 생성

#데이터베이스 설정을 따로 관리하는 파일 config.py
