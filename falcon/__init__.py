import sys

sys.path.append('falcon')
from common import q, sqnorm
from fft import add, sub, mul, div, neg, fft, ifft
from fft import add_fft, mul_fft
from ntt import mul_zq, div_zq, add_zq
from helper import ManhattanNorm, hash_to_point, verify_1, H1
from .falcon import SecretKey