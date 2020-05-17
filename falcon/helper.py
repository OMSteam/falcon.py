import hashlib
from common import q

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