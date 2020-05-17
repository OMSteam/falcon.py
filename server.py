from falcon import q
from falcon import add, sub, mul, div, neg, fft, ifft
from falcon import add_fft, mul_fft
from falcon import mul_zq, div_zq, add_zq
from falcon import SecretKey
from falcon import hash_to_point, ManhattanNorm, verify_1

from random import randint, random, gauss, choice
from math import pi, sqrt, floor, ceil, exp
import pickle
from base64 import b64encode, b64decode
import mysql.connector
import tornado.ioloop
import tornado.web
import json
from time import time

class ServerDBWrapper(object):
    CHALLANGE_LENGTH = 100
    CHALLANGE_LIVE = 60*30

    def __init__(self, host, user, passwd):
        self.mydb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database="OMS"
        )
        
    def random_challange(self, length):
        alphabet = [chr(i) for i in list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58))]
        return ''.join([choice(alphabet) for i in range(length)])
        
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
            Challange VARCHAR({}) NOT NULL,
            ChallangeTime INT UNSIGNED NOT NULL
        )""".format(self.CHALLANGE_LENGTH))
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
        cursor.execute("INSERT INTO Users(UID, PK, StockCount, RevokeDate, Challange, ChallangeTime) VALUES('{UID}', '{PK}', {stocks}, NULL, '{challange}', {time})".format(
            UID=UIDbase64, 
            PK=PKbase64, 
            stocks=stocks, 
            challange=self.random_challange(self.CHALLANGE_LENGTH), 
            time=time()
            )
        )
        self.mydb.commit()
        cursor.close()
        
    def get_challange_and_PK(self, UID):
        cursor = self.mydb.cursor()
        UIDbase64 = b64encode(pickle.dumps(UID)).decode('ascii')
        cursor.execute("SELECT Challange, ChallangeTime, PK FROM Users WHERE UID='{UID}'".format(UID=UIDbase64)) 
        result = cursor.fetchall()[0]
        cursor.close()
        return result[0], result[1], result[2]
        
    def update_challange(self, UID):
        cursor = self.mydb.cursor()
        UIDbase64 = b64encode(pickle.dumps(UID)).decode('ascii')
        cursor.execute("UPDATE Useres SET Challange='{challange}', ChallangeTime={time} WHERE UID='{UID}'".format(
            UID=UIDbase64,
            challange=self.random_challange(self.CHALLANGE_LENGTH),
            time=time() # fresh time
            )
        ) 
        result = cursor.fetchall()
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
        return hash_to_point(self.keys.n, login.encode('ascii'))

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
        
        cert = s.pkg.GenerateUserCert(uid)
        # return cert to user
        self.write(json.dumps(cert))
        
class PublicParamsHandler(tornado.web.RequestHandler):
    def get(self):
        s = getServer()
        global q
        self.write(json.dumps({"MPK":s.pkg.getMPK(),"n":s.pkg.keys.n,"q":q}))
        
class AuthHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        if not self.request.headers.get('Authorization'):
            print('No auth header')
            self.set_header('WWW-Authenticate', 'CustomAuth')
            return None
        auth = self.request.headers.get('Authorization')
        auth_data = pickle.loads(b64decode(auth))
        login, challange_sig = auth_data[0], auth_data[1]
        # check weahter challcange is fresh
        s = getServer()
        uid = s.pkg.generateUID(login)
        challange, challange_time, pk_base64 = s.db.get_challange_and_PK(uid)
        if (time() - challange_time) > s.db.CHALLANGE_LIVE: # our challange is out of date
            print("User challange is out of date")
            s.db.update_challange(uid)
            challange, _, _ = s.db.get_challange_and_PK(uid)
            self.set_header('WWW-Authenticate', challange)
            return None
        # challange is fresh, check sig
        pk = pickle.loads(b64decode(pk_base64))
        if verify_1(s.pkg.keys.n, challange.encode('ascii'), challange_sig, uid, pk, s.pkg.getMPK()):
            return login
        else:
            print("Invalid challange signature")
            self.set_header('WWW-Authenticate', challange)
        return None
        
class GetSingersInfoHandler(AuthHandler):
    def post(self):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        data = json.loads(self.request.body)
        if "signers" not in data:
            self.set_status(400)
            self.write("Invalid data format")
            return
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
            (r"/public", PublicParamsHandler),
            (r"/pks", GetSingersInfoHandler),
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