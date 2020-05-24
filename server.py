from falcon import q
from falcon import add, sub, mul, div, neg, fft, ifft
from falcon import add_fft, mul_fft
from falcon import mul_zq, div_zq, add_zq
from falcon import SecretKey
from falcon import hash_to_point, ManhattanNorm, verify_1, verify_agg

from random import randint, random, gauss, choice
from math import pi, sqrt, floor, ceil, exp
import pickle
from base64 import b64encode, b64decode
import mysql.connector
import tornado.ioloop
import tornado.web
import json
import os
from time import time
import argparse
import datetime

if not os.path.isfile("server.log"):
    open("server.log", "w").close()
log = open("server.log", 'a')
def log_line(msg):
    global log
    log.write("{time}: {msg}\n".format(time=datetime.datetime.now().time(), msg=msg))
    log.flush()

class ServerDBWrapper(object):
    CHALLANGE_LENGTH = 100
    CHALLANGE_LIVE = 10 #60*30

    def __init__(self, host, user, passwd, clear=False):
        self.clear = clear
        log_line("connecting to database")
        self.mydb = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
            database="OMS"
        )
        log_line("connected")
        
    def random_challange(self, length):
        alphabet = [chr(i) for i in list(range(97, 123)) + list(range(65, 91)) + list(range(48, 58))]
        return ''.join([choice(alphabet) for i in range(length)])
        
    def check_schema(self):
        cursor = self.mydb.cursor()
        if self.clear:
            log_line("dropping tables (clearing database)")
            cursor.execute("DROP TABLE Users")
            cursor.execute("DROP TABLE RegTokens")
            cursor.execute("DROP TABLE Documents")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS Users(
            id VARCHAR(64) PRIMARY KEY,
            PK VARCHAR(10000) NOT NULL,
            StockCount INT NOT NULL,
            RevokeTimestamp INT,
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
        
    def revoke_user(self, login):
        cursor = self.mydb.cursor()
        cursor.execute("UPDATE Users SET RevokeTimestamp={timestamp} WHERE id='{id}'".format(id=login, timestamp=int(time())))
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
        result = cursor.fetchall()
        cursor.close()
        if len(result) != 1:
            raise ValueError("Token {} doesn't exist".format(token))
        result = result[0][0]
        return result
        
    def add_user(self, login, PK, stocks):
        cursor = self.mydb.cursor()
        PKbase64 = b64encode(pickle.dumps(PK)).decode('ascii')
        cursor.execute("INSERT INTO Users(id, PK, StockCount, RevokeTimestamp, Challange, ChallangeTime) VALUES('{id}', '{PK}', {stocks}, NULL, '{challange}', {time})".format(
            id=login, 
            PK=PKbase64, 
            stocks=stocks, 
            challange=self.random_challange(self.CHALLANGE_LENGTH), 
            time=time()
            )
        )
        self.mydb.commit()
        cursor.close()
        
    def get_challange_and_PK(self, id):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT Challange, ChallangeTime, PK FROM Users WHERE id='{id}'".format(id=id)) 
        result = cursor.fetchall()
        cursor.close()
        if len(result) != 1:
            raise ValueError("User id doesn't exist in the database ({})".format(id))
        result = result[0]
        return result[0], result[1], result[2]
        
    def is_user_revoked(self, id):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT 1 FROM Users WHERE id='{id}' AND RevokeTimestamp IS NOT NULL".format(id=id))
        result = cursor.fetchall()
        cursor.close()
        return len(result) == 1
        
    def update_challange(self, id):
        cursor = self.mydb.cursor()
        cursor.execute("UPDATE Users SET Challange='{challange}', ChallangeTime={time} WHERE id='{id}'".format(
            id=id,
            challange=self.random_challange(self.CHALLANGE_LENGTH),
            time=time() # fresh time
            )
        )
        self.mydb.commit()
        cursor.close()
        
    def get_pbulic_keys(self, signers_list, timestamp):
        # prepare query filter
        flt = ' OR '.join(["id='{}'".format(signer) for signer in signers_list])
        print("DEBUG filter: {}".format(flt))
    
        cursor = self.mydb.cursor()
        cursor.execute("SELECT id, PK FROM Users WHERE ({filter}) AND (RevokeTimestamp IS NULL OR RevokeTimestamp>{timestamp})".format(filter=flt, timestamp=timestamp)) 
        result = cursor.fetchall()
        cursor.close()
        public_keys = [(e[0], e[1]) for e in result] # list of tuples (id, PK)
        public_keys_map = {}
        for (login, public_key) in public_keys:
            public_keys_map[login] = pickle.loads(b64decode(public_key))
        return public_keys_map
        
    def get_ordered_signers_list(self, timestamp):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT id FROM Users WHERE RevokeTimestamp>{timestamp} OR RevokeTimestamp IS NULL ORDER BY StockCount".format(timestamp=timestamp) )
        result = cursor.fetchall()
        cursor.close()
        return [e[0] for e in result]
        
    def add_document(self, name, signers_list):
        cursor = self.mydb.cursor()
        cursor.execute("INSERT INTO Documents(Name, SignersList, CurrentSigner) VALUES('{name}', '{signers}', 0)".format(
            name=name, 
            signers=b64encode(pickle.dumps(signers_list)).decode('ascii'), 
            )
        )
        self.mydb.commit()
        cursor.close()
        
    def get_documents_to_sign(self, id):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT Name, SignersList, CurrentSigner FROM Documents WHERE CurrentSigner<>-1")
        result = cursor.fetchall()
        cursor.close()
        return [e[0] for e in result if pickle.loads(b64decode(e[1]))[e[2]] == id] # we need those document names where current signer e[1][e[2]] (i.e. SignersList[CurSigner]) is equal to the given id
        
    def get_cur_signer_for_document(self, document_name):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT SignersList, CurrentSigner FROM Documents WHERE Name='{doc}' AND CurrentSigner<>-1".format(doc=document_name))
        result = cursor.fetchall()
        cursor.close()
        if len(result) == 0:
            raise ValueError("Docuemnt doesn't exist or is already in the library (signed)")
        result = result[0]
        print(result)
        return pickle.loads(b64decode(result[0]))[result[1]]
        
    def is_signature_finished(self, document_name):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT 1 FROM Documents WHERE Name='{doc}' AND CurrentSigner=-1".format(doc=document_name))
        result = cursor.fetchall()
        cursor.close()
        return len(result) == 1
        
    def get_signers_list(self, document_name):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT SignersList, CurrentSigner FROM Documents WHERE Name='{doc}'".format(doc=document_name))
        result = cursor.fetchall()
        cursor.close()
        if len(result) != 1:
            raise ValueError("Document doesn't exist")
        result = result[0]
        return pickle.loads(b64decode(result[0])), result[1]
        
    def increase_current_signer(self, document_name):
        signers_list, current_signer = self.get_signers_list(document_name)
        current_signer += 1
        if current_signer == len(signers_list):
            log_line("Document {} signing is complete!".format(document_name))
            current_signer = -1
        if current_signer != -1:
            log_line("Next signer in signing queue for document {} is {}".format(document_name, signers_list[current_signer]))
        cursor = self.mydb.cursor()
        cursor.execute("UPDATE Documents SET CurrentSigner={cur_signer} WHERE Name='{doc}'".format(cur_signer=current_signer, doc=document_name))
        self.mydb.commit()
        cursor.close()
        
    def get_signed_documents(self):
        cursor = self.mydb.cursor()
        cursor.execute("SELECT Name FROM Documents WHERE CurrentSigner=-1")
        result = cursor.fetchall()
        cursor.close()
        return [e[0] for e in result]
        
class PKG(object):
    PKG_params = 'server_{}.params'

    def __init__(self, t, regen=False):
        keys = None
        if not os.path.isfile(self.PKG_params.format(t)) or regen:
            log_line("generating schema parameters (t = {})".format(t))
            keys = SecretKey(1 << t)
            log_line("parameters were generated")
            pickle.dump(keys, open(self.PKG_params.format(t), 'wb'))
        else:
            keys = pickle.load(open(self.PKG_params.format(t), 'rb'))
            log_line("parameters were restored from file")
            
        self.keys = keys
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
"""
API:
POST-request. 3 arguments:
    1. Token string - passed via uri (domain/register/<TOKEN_STRIN>
    2. Admin password - in Json-dictionary passed via request body (key "pwd")
    3. Stock number - in Json-dictionary (key "num")
"""
class AddTokenHandler(tornado.web.RequestHandler):
    def post(self, token):
        data = json.loads(self.request.body)
        print(token)
        if "pwd" not in data or data["pwd"] != "secret" or "num" not in data:
            self.set_status(401)
            self.write("Go away")
            return
        s = getServer()
        try:
            s.db.add_token(token, int(data["num"]))
        except mysql.connector.errors.IntegrityError as e:
            self.set_status(400)
            self.write("Dublicate")
            return
        log_line("token {} was added by admin".format(token))
        self.write("ok")
        
class RevokeHandler(tornado.web.RequestHandler):
    def post(self, login):
        data = json.loads(self.request.body)
        if "pwd" not in data or data["pwd"] != "secret":
            self.set_status(401)
            self.write("Go away")
            return
        s = getServer()
        s.db.revoke_user(login)
        log_line("user {} signing privelege was revoked".format(login))
        self.write("ok")

"""
API:
POST-request. 3 arguments:
    1. Token string - passed via uri (domain/register/<TOKEN_STRIN>
    2. Chosen login - in Json-dictionary passed via request body (key "login")
    3. Generated Public Key - in Json-dictionary (key "PK")
"""
class RegisterHandler(tornado.web.RequestHandler):
    def post(self, token):
        data = json.loads(self.request.body)
        if "login" not in data or "pk" not in data:
            self.set_status(400)
            self.write("Invalid data format")
            return
        pk = json.loads(b64decode(data["pk"]).decode('ascii'))
        if not isinstance(pk, list):
            self.set_status(400)
            self.write("Invalid pk format ({})".format(type(pk)))
            return 
        s = getServer()
        if not s.db.check_token(token):
            self.set_status(401)
            self.write("Invalid token ({})".format(token))
            return
        stock_num = s.db.get_stock_num(token)
        try:
            s.db.add_user(data["login"], pk, stock_num)
        except mysql.connector.errors.IntegrityError as e:
            self.set_status(400)
            self.write("Dublicate login")
            return
        s.db.del_token(token)
        
        cert = s.pkg.GenerateUserCert(s.pkg.generateUID(data["login"]))
        
        log_line("new user registered with id {}".format(data["login"]))
        # return cert to user
        self.write(json.dumps(cert))

"""
API:
GET-request. No args.
Returns public parameters (n, q, h).
"""
class PublicParamsHandler(tornado.web.RequestHandler):
    def get(self):
        s = getServer()
        global q
        log_line("public parameters were requested")
        self.write(json.dumps({"MPK":s.pkg.getMPK(),"n":s.pkg.keys.n,"q":q}))
        
"""
This class implements requests authorization logic (challanged based authorization)
"""
class AuthHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        if not self.request.headers.get('Authorization'):
            log_line('Authorization. No auth header')
            self.set_header('WWW-Authenticate', 'CustomAuth')
            return None
        auth = self.request.headers.get('Authorization')
        auth_data = pickle.loads(b64decode(auth))
        login, challange_sig = auth_data[0], auth_data[1]
        
        log_line("user {} request authorization check".format(login))
        
        s = getServer()
        # check whether this user is revoked
        if s.db.is_user_revoked(login):
            log_line("This user is revoked ({})".format(login))
            self.set_header('WWW-Authenticate', 'CustomAuth')
            return None
        # check if challcange is fresh
        challange, challange_time, pk_base64 = s.db.get_challange_and_PK(login)
        if (time() - challange_time) > s.db.CHALLANGE_LIVE: # our challange is out of date
            log_line("User challange is out of date")
            s.db.update_challange(login)
            challange, _, _ = s.db.get_challange_and_PK(login)
            self.set_header('WWW-Authenticate', challange)
            return None
        # challange is fresh, check sig
        pk = pickle.loads(b64decode(pk_base64))
        uid = s.pkg.generateUID(login)
        if verify_1(s.pkg.keys.n, challange.encode('ascii'), challange_sig, uid, pk, s.pkg.getMPK()):
            log_line("Request {} was authorized for user {}".format(self.request.uri, login))
            return login
        else:
            log_line("Authorization failed. Invalid challange signature")
            self.set_header('WWW-Authenticate', challange)
        return None

"""
API:
POST-request. 2 argument:
    1. signers list - Json-list of logins whose PKs are will be returned.
    2. timestamp - Timestamp retrieved from signed document. PKs of users that were revoked after this timestamp won't be returned (those users should not have signed this document.
Returns json-dictionary of PKs {"id" : PK}.
"""
class GetPublicKeysHandler(AuthHandler):
    def post(self):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        data = json.loads(self.request.body)
        if "signers" not in data or "timestamp" not in data:
            self.set_status(400)
            self.write("Invalid data format")
            return
        signers = data["signers"]
        timestamp = data["timestamp"]
        if not isinstance(timestamp, int):
            self.set_status(400)
            self.write("Invalid timestamp format")
            return
        # check if list is provided
        if not isinstance(signers, list):
            self.set_status(400)
            self.write("Invalid signers list format")
            return
        # check that each element in the list is an instance of str
        for s in signers:
            if not isinstance(s, str):
                self.set_status(400)
                self.write("Invalid signers list format")
                return
        s = getServer()
        signers_info_map = s.db.get_pbulic_keys(signers, timestamp)
        log_line("Returning PKs for ids: {}".format(signers))
        self.write(json.dumps(signers_info_map))

"""
API:
POST-request. 1 argument (file):
    PDF file to be uploaded should be sent as multipart data.
"""
class AddDocumentHandler(AuthHandler):
    def post(self):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        if len(list(self.request.files.keys())) != 1:
            self.set_status(400)
            self.write("Only single file submission is supported")
            return
        fname = list(self.request.files.keys())[0]
        extn = os.path.splitext(fname)[1]
        if extn != '.pdf':
            self.set_status(400)
            self.write("Unsupported file extension")
            return
        s = getServer()
        
        # create timestamp
        timestamp = int(time())
        
        signers = s.db.get_ordered_signers_list(timestamp)
        print("Signers list for new doc: {}".format(signers))
        try:
            s.db.add_document(fname, signers)
        except mysql.connector.errors.IntegrityError as e:
            self.set_status(400)
            self.write("Dublicate document name")
            return
        # serialize timestamp
        timestamp_ser = timestamp.to_bytes(8, byteorder='little')
        # now we can save file to files directory
        print("DOC LEN")
        print(self.request.files[fname][0]['body'])
        with open(os.path.join("files", fname), 'wb') as fp:
            fp.write(timestamp_ser + self.request.files[fname][0]['body']) # add timestamp to document
        with open(os.path.join("signatures", fname + '.sig'), 'w') as fp:
            json.dump([], fp)
        log_line("User {} uploaded file {}. Signers list: {}".format(self.current_user, fname, signers))
        self.write('ok')
        
"""
API:
GET-request. No arguments.
Returns Json-list of documents that are pending for signing by current user (for whom this request was authorized).
"""
class SignQueueHandler(AuthHandler):
    def get(self):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        id = self.current_user
        s = getServer()
        log_line("User {} requested documents list for signing".format(self.current_user))
        self.write(json.dumps(s.db.get_documents_to_sign(id)))

"""
API:
GET-request. 1 argument:
    1. File name is passed via URI string.
"""
class FileDownloadHandler(tornado.web.StaticFileHandler, AuthHandler):
    async def get(self, name):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        log_line("User {} downloads {}".format(self.current_user, name))
        await super().get(name)

"""
API:
GET-request. 1 argument:
    1. File name is passed via URI string.
Current aggregated signature is returned only if the user who authorized this request is the current user in signing queue for this document. If he is not then 400 status will be returned.
"""
class GetAggSignatureHandler(tornado.web.StaticFileHandler, AuthHandler):
    async def get(self, name):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        s = getServer()
        try:
            cur_signer = s.db.get_cur_signer_for_document(name)
        except ValueError as e:
            self.set_status(400)
            self.write("Document is not available for signing.")
            return
        if self.current_user != cur_signer:
            self.set_status(400)
            self.write("Go away... You're not our current signer")
            return
        log_line("user {} requests current aggregate for {}".format(self.current_user, name))
        await super().get(name + ".sig")   

"""
API:
GET-request. 1 argument:
    1. File name is passed via URI string.
Returns aggregated signature for signed document (signing proccess for this document should be finished). Any authorized user should use this request to retrive signature for document verification.
"""
class GetFinalSignatureHandler(tornado.web.StaticFileHandler, AuthHandler):
    async def get(self, name):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        s = getServer()
        if not s.db.is_signature_finished(name):
            self.set_status(400)
            self.write("Document doesn't exist or its signature is not fully aggregated yet")
            return
        log_line("user {} requests aggregated signature for {}".format(self.current_user, name))
        await super().get(name + ".sig")   

"""
API:
POST-request. 2 argument:
    1. File name is passed via URI string.
    2. New aggregate signature part is passed in json body (key "sig")
This request can be used only by current signer (from document's signing queue) to add new signature part (aggregate his part of the signature). If the signature is valid (server performs the check) than the signing process will proceed to the next user in the signing queue.
"""
class SignHandler(AuthHandler):
    def post(self, name):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        s = getServer()
        try:
            cur_signer = s.db.get_cur_signer_for_document(name)
        except ValueError as e:
            self.set_status(400)
            self.write("Document is not available for signing.")
            return
        if self.current_user != cur_signer:
            self.set_status(400)
            self.write("Go away... You're not our current signer")
            return
        data = json.loads(self.request.body)
        if "sig" not in data:
            self.set_status(400)
            self.write("Invalid request format")
            return
        sig = data["sig"]
        sig_agg = json.load(open(os.path.join('signatures', name + '.sig'), 'r'))
        msg = open(os.path.join('files', name), 'rb').read()
        
        signers_list, cur_index = s.db.get_signers_list(name)
        cur_list = signers_list[:cur_index+1]
        
        public_keys_map = s.db.get_pbulic_keys(cur_list, 0)
        
        uid_hashes = [s.pkg.generateUID(login) for login in cur_list]
        signers_info = [(uid_hashes[i], public_keys_map[cur_list[i]]) for i in range(len(cur_list))]
        print(sig_agg + [sig])
        if not verify_agg(
            s.pkg.keys.n,
            msg,
            sig_agg + [sig],
            signers_info,
            s.pkg.getMPK()
            ):
            self.set_status(400)
            log_line("User {} provided invalid aggregate for {}".format(self.current_user, name))
            self.write("Invalid signature")
            return
        log_line('User {} provided valid aggregate for {}'.format(self.current_user, name))
        
        json.dump(sig_agg + [sig], open(os.path.join('signatures', name + '.sig'), 'w')) # update aggregated signature
        s.db.increase_current_signer(name) # set next signer (or finish signing)
        self.write('ok')

"""
API:
GET-request. 1 argument:
    1. File name is passed via URI string.
This request returns the ordered list of document's signers (that was generated during upload based on the users' stock shares). This request should be used by clients in order to verify aggregated signature.
"""
class GetDocumentSighersHandler(AuthHandler):
    def get(self, name):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        s = getServer()
        try:
            signers = s.db.get_signers_list(name)[0]
        except ValueError as e:
            self.set_status(404)
            self.write("Document doesn't exist")
            return
        log_line("User {} requested signers list for document {}".format(self.current_user, name))
        self.write(json.dumps(signers))

"""
API:
GET-request. No arguments.
Returns json-list with names of all signed documents.
"""
class GetSignedDocuments(AuthHandler):
    def get(self):
        if self.current_user is None:
            self.set_status(401)
            self.write("Unauthorized")
            return
        s = getServer()
        log_line("User {} requested signed documents list".format(self.current_user))
        self.write(json.dumps(s.db.get_signed_documents()))
        
class Server(object):
    def __init__(self, t, dbhost, dbuser, dbpass, regen=False, cleardb=False):
        self.pkg = PKG(t, regen=regen)
        self.db = ServerDBWrapper(dbhost, dbuser, dbpass, clear=cleardb)
        self.db.check_schema()
        
    def make_app(self):
        return tornado.web.Application([
            (r"/register/(.*)", RegisterHandler),
            (r"/addtoken/(.*)", AddTokenHandler),
            (r"/revoke/(.*)", RevokeHandler),
            (r"/public", PublicParamsHandler),
            (r"/pks", GetPublicKeysHandler),
            (r"/adddocument", AddDocumentHandler),
            (r"/signqueue", SignQueueHandler),
            (r"/getdocument/(.*)", FileDownloadHandler, {"path": "files"}),
            (r"/getaggsig/(.*)", GetAggSignatureHandler, {"path": "signatures"}),
            (r"/sign/(.*)", SignHandler),
            (r"/getfinishedsig/(.*)", GetFinalSignatureHandler, {"path": "signatures"}),
            (r"/getdocumentsigners/(.*)", GetDocumentSighersHandler),
            (r"/allsigned", GetSignedDocuments),
        ])

def getServer():
    global s
    return s
    
class NegateAction(argparse.Action):
    def __call__(self, parser, ns, values, option):
        setattr(ns, self.dest, option[2:4] != 'no')
    
def cli():
    parser = argparse.ArgumentParser(description='OMS server')
    parser.add_argument('parameter', metavar='param', type=int, help='security paramter t')
    parser.add_argument('--dbhost', help='MySQL host name', required=True)
    parser.add_argument('--dbuser', help='MySQL user', required=True)
    parser.add_argument('--dbpass', help='MySQL password', required=True)
    parser.add_argument('--port', type=int, help='Server listen port', required=True)
    parser.add_argument('--regen', dest='regen', action=NegateAction, help='regenerate schema parameters', nargs=0)
    parser.add_argument('--cleardb', dest='cleardb', action=NegateAction, help='clears database', nargs=0)
    return parser

def main():
    args = cli().parse_args()
    
    global s
    s = Server(args.parameter, args.dbhost, args.dbuser, args.dbpass, regen=args.regen, cleardb=args.cleardb)
    app = s.make_app()
    app.listen(args.port)
    log_line("starting listening on port {}".format(args.port))
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()