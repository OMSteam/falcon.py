from falcon import q
from falcon import add, sub, mul, div, neg, fft, ifft
from falcon import add_fft, mul_fft
from falcon import mul_zq, div_zq, add_zq
from falcon import SecretKey
from falcon import hash_to_point, ManhattanNorm, verify_1, H1, verify_agg

from random import randint, random, gauss, choice
from math import pi, sqrt, floor, ceil, exp
import pickle
from base64 import b64encode, b64decode
import json
import requests
import sys, os
import argparse

class Client(object):
    """
    uid - user ID
    t - schema parameter
    MPK - aka h from falcon
    """
    def __init__(self, login, serverURL):
        self.login = login
        self.url = serverURL
        r = requests.get('{}/public'.format(self.url))
        if r.status_code != 200:
            raise ValueError("Server responded with code other than 200")
        public = json.loads(r.content)
        self.n = public["n"]
        self.MPK = public["MPK"]
        self.sigma = 1.17 * sqrt(q / (2. * self.n))
        
    def generateUID(self, login):
        return hash_to_point(self.n, login.encode('ascii'))
        
    def set_uid(self, uid):
        self.uid = uid
        
    def gen_sk(self):
        s1 = [int(round(gauss(0, self.sigma))) for i in range(self.n)]
        s2 = [int(round(gauss(0, self.sigma))) for i in range(self.n)]

        self.pk = add_zq(s1, mul_zq(s2, self.MPK)) # maybe we should use fft (we'll check if sth doesn't work)
        self.sk = (s1, s2)
        
    def export_sk(self):
        return pickle.dump(self.sk, open(self.login + '.sk', 'wb'))
        
    def load_sk(self):
        self.sk = pickle.load(open(self.login + '.sk', 'rb'))
        s1 = self.sk[0]
        s2 = self.sk[1]
        self.pk = add_zq(s1, mul_zq(s2, self.MPK))
        
    def build_auth_info(self, challange):
        self.auth_info = b64encode(pickle.dumps([self.login, self.sign_1(challange)])).decode('ascii')

    def sign_1(self, m):
        sigma = self.sigma
        # generating random elements from (Z_q)^n
        y1 = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y2 = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y1a = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y2a = [int(round(gauss(0, sigma))) for i in range(self.n)]
        # compute e as H1 hash from message and random elements put throgh trapdoor one-way func (f_h)
        e = H1(self.n, add_zq(y1, mul_zq(y2, self.MPK)), add_zq(y1a, mul_zq(y2a, self.MPK)), m)
        # !!!!!!!!!! TODO! Check who's who (cert and user's secret key) !!!!!!!!!!!!!!
        s1a = self.sk[0]
        s2a = self.sk[1]
        s1 = self.cert[0]
        s2 = self.cert[1]
        z = (
            add_zq(mul_zq(s1, e), y1),
            add_zq(mul_zq(s2, e), y2),
            add_zq(mul_zq(s1a, e), y1a),
            add_zq(mul_zq(s2a, e), y2a)
        )
        return (e, z)

    def sign_agg_step(self, m, agg_sig):
        curSig = self.sign_1(
            pickle.dumps([m] + agg_sig) # cast agg_sig signature chain to byte array
        )
        return curSig

    def verify_agg(self, m, agg_sig, signers_info, MPK):
        if len(agg_sig) != len(signers_info):
            return False
        for i in range(len(agg_sig)):
            curCheckMsg = pickle.dumps([m] + agg_sig[:i])
            if not self.verify_1(
                curCheckMsg, agg_sig[i],
                signers_info[i][0], # UID
                signers_info[i][1], # Public Key
                MPK
            ):
                return False
        return True
        
    def add_token(self, token, num):
        r = requests.post('{}/addtoken/{}'.format(self.url, token), data=json.dumps({'pwd':'secret', 'num':num}))
        if r.status_code != 200:
            raise ValueError("Error {}: {}".format(r.status_code, r.content))
        
    def register(self, token):
        r = requests.post('{}/register/{}'.format(self.url, token), data=json.dumps({'login': self.login, 'pk':b64encode(json.dumps(self.pk).encode('ascii')).decode('ascii')}))
        if r.status_code != 200:
            raise ValueError("Error {}: {}".format(r.status_code, r.content))
        self.cert = json.loads(r.content)
        return self.cert
    
    def export_cert(self):
        open(self.login + '.cert', 'wb').write(pickle.dumps(self.cert))
        
    def load_cert(self):
        self.cert = pickle.loads(open(self.login + '.cert', 'rb').read())
        
    def add_document(self, file):
        r = requests.post('{}/adddocument'.format(self.url), files={file: open(file, 'rb')} , headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.post('{}/adddocument'.format(self.url), files={file: open(file, 'rb')}, headers={'Authorization' : self.auth_info})
            print(r)
            print(r.content)
            
    def get_sign_queue(self):
        r = requests.get('{}/signqueue'.format(self.url), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/signqueue'.format(self.url), headers={'Authorization' : self.auth_info})
            print(r)
        return json.loads(r.content)
        
    def get_document(self, name):
        r = requests.get('{}/getdocument/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/getdocument/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
            print(r)
        return r.content
                
    def get_agg_signature(self, name):
        r = requests.get('{}/getaggsig/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/getdocument/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
            print(r)
        if r.status_code != 200:
            raise ValueError("Error {}: {}".format(r.status_code, r.content))
        print(r.content)
        return json.loads(r.content)
        
    def get_finished_signature(self, name):
        r = requests.get('{}/getfinishedsig/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/getfinishedsig/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
            print(r)
        if r.status_code != 200:
            raise ValueError("Error {}: {}".format(r.status_code, r.content))
        return json.loads(r.content)
        
    def sign_docuemtn(self, name):
        msg = self.get_document(name)
        agg_sig = self.get_agg_signature(name)
        cur_sig = self.sign_agg_step(msg, agg_sig)
        r = requests.post('{}/sign/{}'.format(self.url, name), headers={'Authorization' : self.auth_info}, data=json.dumps({'sig':cur_sig}))
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.post('{}/sign/{}'.format(self.url, name), headers={'Authorization' : self.auth_info}, data=json.dumps({'sig':cur_sig}))
            print(r)
        print(r)
        print(r.content)
        
    def get_signers(self, name):
        r = requests.get('{}/getdocumentsigners/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/getdocumentsigners/{}'.format(self.url, name), headers={'Authorization' : self.auth_info})
            print(r)
        return json.loads(r.content)
        
    def get_public_keys(self, signers_list):
        print(signers_list)
        r = requests.post('{}/pks'.format(self.url), headers={'Authorization' : self.auth_info}, data=json.dumps({"signers":signers_list}))
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.post('{}/pks'.format(self.url), headers={'Authorization' : self.auth_info}, data=json.dumps({"signers":signers_list}))
            print(r)
        if r.status_code != 200:
            raise ValueError("Error {}: {}".format(r.status_code, r.content))
        return json.loads(r.content)
        
    def verify_document(self, name):
        msg = self.get_document(name)
        sig_agg = self.get_finished_signature(name)
        signers = self.get_signers(name)
        pk_map = self.get_public_keys(signers)
        
        signers_info = [(self.generateUID(signers[i]), pk_map[signers[i]]) for i in range(len(signers))]
        return verify_agg(
            self.n,
            msg,
            sig_agg,
            signers_info,
            self.MPK
        )
        
    def get_all_signed(self):
        r = requests.get('{}/allsigned'.format(self.url), headers={'Authorization' : self.auth_info})
        if r.status_code == 401:
            self.build_auth_info(r.headers['Www-Authenticate'].encode('ascii'))
            print("Unauthorized")
            challange = r.headers['Www-Authenticate']
            print("Challange: {}".format(challange))
            r = requests.get('{}/allsigned'.format(self.url), headers={'Authorization' : self.auth_info})
            print(r)
        return json.loads(r.content)
        
def cli():
    commands = ['addtoken', 'register', 'signqueue', 'adddocument', 'sign', 'validate', 'allsigned']
    parser = argparse.ArgumentParser(description='Test OMS client')
    parser.add_argument('command', metavar='command', type=str, choices=commands, help='test client command ({})'.format('/'.join(commands)))
    parser.add_argument('--url', help='OMS server URL', required=True)
    parser.add_argument('--id', help='client id')
    parser.add_argument('--file', help='path to file')
    parser.add_argument('--num', help='stocks num')
    parser.add_argument('--token', help='token')
    parser.add_argument('--name', help='docuement name (on server)')
    return parser

def main():
    args = cli().parse_args()
    
    # admin commands
    if args.command == 'addtoken':
        if args.token is None or args.num is None:
            print("Token name and stock number are required for this command!")
            sys.exit(1)
        client = Client('any', args.url)
        client.add_token(args.token, args.num)
        return
    
    # user commands
    if args.id is None:
        print("ID is needed for user commands!")
        sys.exit(1)
    login = args.id
    client = Client(login, args.url)

    if args.command == 'register':
        if args.token is None:
            print("token is required to register")
            sys.exit(1)
        client.gen_sk()
        client.export_sk()
        client.register(args.token)
        client.export_cert()
        return
    # authenticated commands    
    if not os.path.isfile(login + '.sk') or not os.path.isfile(login + '.cert'):
        print("No .sk and/or .cert found. You need to register first")
        sys.exit(1)
    client.load_sk()
    client.load_cert()
    client.build_auth_info(b'empty')
    
    if args.command == 'signqueue':
        sign_queue = client.get_sign_queue()
        if len(sign_queue) > 0:
            print("{}'s documents for signing:".format(login))
            for d in sign_queue:
                print("\t{doc}: currennt aggregate is {agg}".format(doc=d, agg=client.get_agg_signature(d)))
        else:
            print("{} has no documents to sign".format(login))
        
    elif args.command == 'adddocument':
        if args.file is None:
            print("File is required for upload!")
            sys.exit(1)
        if args.file not in os.listdir('.'):
            print("File should be located in the same directory with the script!")
            sys.exit(1)
        client.add_document(args.file)
        
    elif args.command == "sign":
        if args.name is None:
            print("Docuemtn name was not provided!")
            sys.exit(1)
        client.sign_docuemtn(args.name)
        
    elif args.command == "validate":
        if args.name is None:
            print("Docuemtn name was not provided!")
            sys.exit(1)
            
        result = client.verify_document(args.name)
        if result:
            print("Docuement signature is valid")
        else:
            print("Docuement signature is invalid")
            
    elif args.command == "allsigned":
        signed = client.get_all_signed()
        print("Signed documents: {}".format(signed))
        
    

if __name__ == "__main__":
    main()