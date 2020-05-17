from falcon import q
from falcon import add, sub, mul, div, neg, fft, ifft
from falcon import add_fft, mul_fft
from falcon import mul_zq, div_zq, add_zq
from falcon import SecretKey
from falcon import hash_to_point, ManhattanNorm

from random import randint, random, gauss
from math import pi, sqrt, floor, ceil, exp
import pickle
from base64 import b64encode, b64decode
import mysql.connector
import tornado.ioloop
import tornado.web
import json

class ServerDBWrapper(object):
    def __init__(self, host, user, passwd):
        self.mydb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database="OMS"
        )
        
    def check_schema(self):
        cursor = self.mydb.cursor()
        #cursor.execute("DROP TABLE Users")
        #cursor.execute("DROP TABLE RegTokens")
        #cursor.execute("DROP TABLE Documents")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS Users(
            num INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            UID VARCHAR(10000) NOT NULL,
            PK VARCHAR(10000) NOT NULL,
            StockCount INT NOT NULL,
            RevokeDate DATETIME,
            Challange VARCHAR(100) NOT NULL
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS RegTokens(
            Token VARCHAR(124) PRIMARY KEY,
            StockCount INT NOT NULL
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS Documents(
            Name VARCHAR(100) PRIMARY KEY,
            SignersList VARCHAR(10000) NOT NULL,
            CurrentSigner INT NOT NULL
        )""")
    
    def add_token(self, token, stock_num):
        cursor = self.mydb.cursor()
        cursor.execute("INSERT INTO RegTokens(Token, StockCount) VALUES('{token}', {stock})".format(token=token, stock=stock_num))
        cursor.close()
        self.mydb.commit()
        
    def del_token(self, token):
        cursor = self.mydb.cursor()
        cursor.execute("DELETE FROM RegTokens WHERE Token='{token}'".format(token=token))
        self.mydb.commit()
        cursor.close()
    
    def check_token(self, token):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT 1 FROM RegTokens WHERE Token='{token}'".format(token=token)) # todo validate input
        result = len(cursor.fetchall()) != 0
        cursor.close()
        return result
        
    def get_stock_num(self, token):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT StockCount FROM RegTokens WHERE Token='{token}'".format(token=token)) # todo validate input
        result = cursor.fetchall()[0][0]
        cursor.close()
        return result
        
    def UID_exists(self, UID):
        cursor = self.mydb.cursor()
        UIDbase64 = b64encode(pickle.dumps(UID)).decode('ascii')
        cursor.execute("SELECT 1 FROM Users WHERE UID='{UID}'".format(UID=UIDbase64)) # todo validate input
        result = len(cursor.fetchall()) != 0
        cursor.close()
        return result
        
    def add_user(self, UID, PK, stocks):
        cursor = self.mydb.cursor()
        UIDbase64 = b64encode(pickle.dumps(UID)).decode('ascii')
        PKbase64 = b64encode(pickle.dumps(PK)).decode('ascii')
        cursor.execute("INSERT INTO Users(UID, PK, StockCount, RevokeDate) VALUES('{UID}', '{PK}', {stocks}, NULL)".format(UID=UIDbase64, PK=PKbase64, stocks=stocks))
        self.mydb.commit()
        cursor.close()

class PKG(object):
    def __init__(self, t):
        self.keys = SecretKey(1 << t)
        self.users_list = {}
        self.salt = None

    """
    PKG (aka server) will provide users with unique identificators
    """
    def generateUID(self, login):
        return self.keys.hash_to_point(login, 'login salt')

    def getMPK(self):
        return self.keys.h

    def GenerateUserCert(self, uid):
        return self.keys.sample_preimage_fft(uid)

# ------------------- SERVER -----------------------
class AddTokenHandler(tornado.web.RequestHandler):
    def post(self, token):
        data = json.loads(self.request.body)
        print(token)
        if "pwd" not in data or data["pwd"] != "secret" or "num" not in data:
            self.set_status(400)
            self.write("Go away")
            return
        s = getServer()
        try:
            s.db.add_token(token, int(data["num"]))
        except mysql.connector.errors.IntegrityError as e:
            self.set_status(400)
            self.write("Dublicate")
            return
        self.write("ok")

class RegisterHandler(tornado.web.RequestHandler):
    def post(self, token):
        data = json.loads(self.request.body)
        if "login" not in data or "pk" not in data:
            self.set_status(400)
            self.write("Invalid data format")
            return
        pk = pickle.loads(b64decode(data["pk"]))
        if not isinstance(pk, list):
            self.set_status(400)
            self.write("Invalid pk format ({})".format(type(pk)))
            return 
        s = getServer()
        if not s.db.check_token(token):
            self.set_status(401)
            self.write("Invalid token")
            return
        stock_num = s.db.get_stock_num(token)
        uid = s.pkg.generateUID(data["login"])
        if s.db.UID_exists(uid):
            self.set_status(400)
            self.wrtie("This login is unavailable")
            return
        s.db.add_user(uid, pk, stock_num)
        s.db.del_token(token)
        
        # TODO generate cert and sent it to user
        
        self.write('ok')
        
class AuthHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        if not self.request.headers.get('Authorization'):
            print('No auth header')
            return None
        auth = self.request.headers.get('Authorization')
        auth_data = pickle.loads(b64decode(auth))
        login, challange_sig = auth_data[0], auth_data[1]
        
        
class GetPKsHandler(AuthHandler):
    def post(self):
        data = json.loads(self.request.body)
        if "login" not in data or "pk" not in data:
            self.set_status(400)
            self.write("Invalid data format")
            return
        pk = pickle.loads(b64decode(data["pk"]))
        if not isinstance(pk, list):
            self.set_status(400)
            self.write("Invalid pk format ({})".format(type(pk)))
            return 
        s = getServer()
        if not s.db.check_token(token):
            self.set_status(401)
            self.write("Invalid token")
            return
        stock_num = s.db.get_stock_num(token)
        uid = s.pkg.generateUID(data["login"])
        if s.db.UID_exists(uid):
            self.set_status(400)
            self.wrtie("This login is unavailable")
            return
        s.db.add_user(uid, pk, stock_num)
        s.db.del_token(token)
        self.write('ok')

class Server(object):
    def __init__(self, t):
        self.pkg = PKG(t)
        self.db = ServerDBWrapper('192.168.1.10', 'root', 'rootpassword')
        self.db.check_schema()
        
    def make_app(self):
        return tornado.web.Application([
            (r"/register/(.*)", RegisterHandler),
            (r"/addtoken/(.*)", AddTokenHandler),
            (r"/pks", GetPKsHandler),
        ])

def getServer():
    global s
    return s

def main():
    # TEST AGG SIGN CELL
    global s
    s = Server(4)
    app = s.make_app()
    app.listen(8899)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()