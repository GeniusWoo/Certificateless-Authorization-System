from KGCM import *
from petlib.ec import EcPt
from petlib.ec import EcGroup
from petlib.bn import Bn

from public.hashfunctions import *
from btostr import *
import dill
nameId = 705


# init KGCM
kgcm = KGCM(nameId)

print(type(kgcm.P_pub))
a= str(kgcm.P_pub)
print(a)
byte_string=kgcm.P_pub.export()
print(byte_string)
print(EcPt.from_binary(byte_string,kgcm.G))
b=b_str(byte_string)
print(b)
c=str_b(b)
print(c)
print('!'.encode())
K_id=input("input file name: ")
with open("./kgcdata/{}.txt".format(K_id),"w") as f:
    f.write(b) 