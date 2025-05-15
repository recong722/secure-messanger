dbs = {
    'host': '데이터베이스 IP',
        'user': 'recong',
        'password': 'recong',
        'database': 'project',
        'port': '3306'

}


DB_URL = f"mysql+pymysql://{dbs['user']}:{dbs['password']}@{dbs['host']}:{dbs['port']}/{dbs['database']}?charset=utf8mb4"

#SQLAlchemy에서 MySQL에 연결할 때 사용되는 URL을 생성

#데이터베이스 설정을 따로 관리하는 파일 config.py
#sudo iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
