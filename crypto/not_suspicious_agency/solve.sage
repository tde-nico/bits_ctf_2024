from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import EllipticCurve, GF
import pwn


n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a = -3

b = 41058363725152142129326129780047268409114441015993725554835256314039467401291

E = EllipticCurve(GF(p), [a, b])

P = E(82608569474992041160607468321330734781976984380007427368012865557687600622709, 35069256181227824748874498744049288021402083829396944376506375002277135146766)
Q = E(73715635164746483174925677582577549814394654274863737334365964739059628583962, 109056745950753818921710346904416730969104963723164318521067168664927746119221)

backdoor = 106285652031011072675634249779849270405
backdoor_inv = pow(backdoor, -1, n)


def encrypt(g, t):
	out = []
	for b in t:
		x = next(g)
		out.append(b ^^ x)
	return bytes(out)

def generate(P, Q, s):
	while True:
		r = int((s * P)[0])
		yield from long_to_bytes((r * Q)[0].lift())[2:]
		s = int((r * P)[0])


pt1 = b'This is a test string for debugging'
ct1 = b'\xbd\xfe\xe5`\x1fQGU*\xcf\xc7\xde=\x068\xa6\xa7\x85.\x8a\x81\x8apF\xea\xda\xc2,\xe4\xddS\xa2U\x93\xec'
ct2 = b'\xd7\x80q!X\x03\x0c\x05\x8d\xa5\xc5/MU\xffi>\xab%\xd4\xefeD\xdbYRk"\x94a\xbd\x19\x05&\xd39\x99Y'

pt1 = pt1[0:30]
ct1 = ct1[0:30]

base = pwn.xor(pt1, ct1)
for i in range(53000, 2**16):
	if i % 1000 == 0:
		print(i)
	
	output = int(bytes_to_long(long_to_bytes(i) + base))
	if not E.is_x_coord(output):
		continue
	
	guess_point = E.lift_x(GF(p)(output))
	s1 = (backdoor_inv * guess_point)[0]

	g2 = generate(P, Q, s1)
	key_stream = bytes([int(next(g2)&0xFF) for _ in range(60)])

	flag = pwn.xor(key_stream[5:], ct2)
	if b'BITS' in flag:
		print(flag)
		break

# BITSCTF{N3V3r_811ND1Y_7rU57_574ND4rD5}
