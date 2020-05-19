import hashlib
from common import q

from fft import fft, ifft, sub, neg, add_fft, mul_fft
from ntt import add_zq, mul_zq, div_zq

import pickle

# helper functions

def ManhattanNorm(vec):
    return sum([abs(componenet) for componenet in vec])

def hash_to_point(n, message):
    """Hash a message to a point in Z[x] mod(Phi, q).

    Inspired by the Parse function from NewHope.
    """
    salt = 'some salt'
    global q
    if q > 2 ** 16:
        raise ValueError("The modulus is too large")

    k = (2 ** 16) / q
    # We take twice the number of bits that would be needed if there was no rejection
    emessage = message #message.encode('utf-8')
    esalt = salt.encode('utf-8')
    hash_instance = hashlib.shake_256()
    hash_instance.update(esalt)
    hash_instance.update(emessage)
    digest = hash_instance.hexdigest(int(8 * n))
    hashed = [0 for i in range(n)]
    i = 0
    j = 0
    while i < n:
        # Takes 2 bytes, transform them in a 16 bits integer
        elt = int(digest[4 * j: 4 * (j + 1)], 16)
        # Implicit rejection sampling
        if elt < k * q:
            hashed[i] = elt % q
            i += 1
        j += 1
    return hashed
    
def H1(n, v1, v2, msg):
    k = q//4 # is kinda much smaller than q
    temp = add_zq(add_zq(v1, v2), hash_to_point(n, msg)) # that's just some random stuff
    return [e % (k//n) for e in temp] # we'll take each componenet modulo k//n in order to satisfy Manhattan 
    
def verify_1(n, m, sig, uid, pk, MPK):
    # parsing sig
    e = sig[0]
    z = sig[1]
    z1, z2, z1a, z2a = z[0], z[1], z[2], z[3]

    # restore e
    vev1 = add_zq(add_zq(z1, mul_zq(z2, MPK)), mul_zq(uid, neg(e)))
    vec2 = add_zq(add_zq(z1a, mul_zq(z2a, MPK)), mul_zq(pk, neg(e)))
    e_check = H1(n, vev1, vec2, m)
    #print('e from sig: {}'.format(e))
    #print('e resttored: {}'.format(e_check))
    return e == e_check
    
def verify_agg(n, m, agg_sig, signers_info, MPK):
    if len(agg_sig) != len(signers_info):
        return False
    for i in range(len(agg_sig)):
        curCheckMsg = pickle.dumps([m] + agg_sig[:i])
        if not verify_1(
            n,
            curCheckMsg, agg_sig[i],
            signers_info[i][0], # UID
            signers_info[i][1], # Public Key
            MPK
        ):
            return False
    return True