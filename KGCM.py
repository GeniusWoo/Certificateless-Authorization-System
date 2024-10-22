from petlib.ec import EcGroup
from petlib.bn import Bn

from public.hashfunctions import *

class KGCM:
    # KGCM类：密钥生成中心类，包含KGCM的IDi，Ti，ti，P_pub，oP_pub等信息以及加解密数据处理
    # P, o, d, P_pub
    def __init__(self, nameId):
        self.nameId = nameId
        self.G = EcGroup(nameId)
        self.P, self.o = self.G.generator(),self.G.order()
        self.d = self.G.order().random()
        self.P_pub = self.P.pt_mul(self.d)

    # setting master public and private keys
    def partialKeyExtract(self, Ti, IDi):
        ri = self.G.order().random()
        Ri = self.P.pt_mul(ri)

        dTi = Ti.pt_mul(self.d)

        # partial key
        # mod q  to be done
        ki = ri + self.d*H7(Ri,Ti,IDi) + H3(dTi,IDi)
        print("Keys - Ri :" + str(Ri) + " ki: " + str(ki))

        return Ri,ki

    def printf(self):
        print("P :", self.P)
        print("self.d :", self.d)
        print("P_pub :", self.P_pub)
        
