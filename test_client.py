from falcon import q
from falcon import add, sub, mul, div, neg, fft, ifft
from falcon import add_fft, mul_fft
from falcon import mul_zq, div_zq, add_zq
from falcon import SecretKey
from falcon import hash_to_point, ManhattanNorm, verify_1, H1

from random import randint, random, gauss, choice
from math import pi, sqrt, floor, ceil, exp
import pickle
from base64 import b64encode, b64decode
import json
import requests
import sys, os

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
        
    def set_uid(self, uid):
        self.uid = uid
        
    def gen_sk(self):
        s1 = [int(round(gauss(0, self.sigma))) for i in range(self.n)]
        s2 = [int(round(gauss(0, self.sigma))) for i in range(self.n)]

        self.pk = add_zq(s1, mul_zq(s2, self.MPK)) # maybe we should use fft (we'll check if sth doesn't work)
        self.sk = (s1, s2)
        
    def export_sk(self):
        return pickle.dumps(self.sk)
        
    def load_sk(self, data):
        self.sk = pickle.loads(data)
        s1 = self.sk[0]
        s2 = self.sk[1]
        self.pk = add_zq(s1, mul_zq(s2, self.MPK))
        
    def build_auth_info(self, challange):
        self.auth_info = b64encode(pickle.dumps([self.login, self.sign_1(challange, self.cert, self.MPK)])).decode('ascii')

    def sign_1(self, m, cert, MPK):
        sigma = self.sigma
        # generating random elements from (Z_q)^n
        y1 = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y2 = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y1a = [int(round(gauss(0, sigma))) for i in range(self.n)]
        y2a = [int(round(gauss(0, sigma))) for i in range(self.n)]
        # compute e as H1 hash from message and random elements put throgh trapdoor one-way func (f_h)
        e = H1(self.n, add_zq(y1, mul_zq(y2, MPK)), add_zq(y1a, mul_zq(y2a, MPK)), m)
        # !!!!!!!!!! TODO! Check who's who (cert and user's secret key) !!!!!!!!!!!!!!
        s1a = self.sk[0]
        s2a = self.sk[1]
        s1 = cert[0]
        s2 = cert[1]
        z = (
            add_zq(mul_zq(s1, e), y1),
            add_zq(mul_zq(s2, e), y2),
            add_zq(mul_zq(s1a, e), y1a),
            add_zq(mul_zq(s2a, e), y2a)
        )
        return (e, z)

    def sign_agg_step(self, m, cert, MPK, agg_sig):
        #if len(agg_sig) == 0: # i == 1
        #    pass # should we do anything special in this case?

        curSig = self.sign_1(
            pickle.dumps([m] + agg_sig), # cast agg_sig signature chain to byte array
            cert,
            MPK
        )
        return agg_sig + [curSig]

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
        
    def register(self, token):
        r = requests.post('{}/register/testtoken'.format(self.url, token), data=json.dumps({'login': self.login, 'pk':b64encode(json.dumps(self.pk).encode('ascii')).decode('ascii')}))
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
            print(r.content)
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
            with open(name, 'wb') as fp:
                fp.write(r.content)

def main(login, file):
    #if file not in os.listdir('.'):
    #    print("Invalid file in current directory")
    #    sys.exit(1)
    client = Client(login, "http://localhost:8899")
    if not os.path.isfile(login + '.sk'):
        client.gen_sk()
        open(login + '.sk', 'wb').write(client.export_sk())
    else:
        client.load_sk(open(login + '.sk', 'rb').read())
    if not os.path.isfile(login + '.cert'):
        # we need to register this user
        client.add_token('testtoken', 100)
        client.register('testtoken')
        client.export_cert()
    else:
        client.load_cert()
    client.build_auth_info(b'empty')
    #client.add_document(file)
    client.get_document(file)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])