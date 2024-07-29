from KGCM import *
from KGC import *
from user import *
from btostr import *
from public.hashfunctions import *
from petlib.ec import EcPt
import socket  
from threading import Thread
import time
import json
import pymysql

# ------------------------ Setup Phase -----------------------------
nameId = 705    # 部分主密钥，可重设

# 初始化 KGCM
global kgcm
with open("./kgcmdata/{}.txt".format("KGCM_data"),"r+") as f:
    rdata=f.read()
    print(rdata)
    if rdata:
        nameId=int(rdata.split('!')[0])
        kgcm=KGCM(nameId)
        kgcm.d=Bn.from_decimal(rdata.split('!')[1])
        kgcm.P_pub = kgcm.P.pt_mul(kgcm.d)
    elif rdata=='':
        kgcm=KGCM(nameId)
        w_list=[str(nameId),str(kgcm.d)]
        write_data='!'.join(w_list)
        f.write(write_data) 

global KGC_name
global login_state
login_state=0
ADDRESS = ('127.0.0.1', 8712)  # 绑定地址
 
g_socket_server = None  # 负责监听的socket
 
g_conn_pool = {}  # 连接池

#database parameter
mysql_host = '127.0.0.1'
mysql_db = 'CLPKC'
mysql_user = 'KGCstudio'
mysql_pwd = '1234'
mysql_table = 'KGC_table'
 
class MYSQL:
    #database operation
    def __init__(self):
        # MySQL
        self.MYSQL_HOST = mysql_host
        self.MYSQL_DB = mysql_db
        self.MYSQ_USER = mysql_user
        self.MYSQL_PWD = mysql_pwd
        self.connect = pymysql.connect(
            host=self.MYSQL_HOST,
            db=self.MYSQL_DB,
            port=3306,
            user=self.MYSQ_USER,
            passwd=self.MYSQL_PWD,
            charset='utf8',
            use_unicode=False
        )
        print(self.connect)
        self.cursor = self.connect.cursor()
 
 
    def insert_kgc(self, KGCid, KGCpw, Ti, IDi, Ri):
        #insert the KGC data
        print("insert begin!\n")
        sql = "insert into {}(`KGCid`, `K_pw`, `Ti`, `Idi`, `Ri`) VALUES (%s, %s, %s, %s, %s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (KGCid, KGCpw, Ti, IDi, Ri))
            self.connect.commit()
            print('kgc data insert successfully!')
        except Exception as e:
            print('e= ', e)
            print('kgc data insert failed')

    def delete_kgc(self,KGCid):
        sql = "delete from {} where KGCid = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (KGCid))
            self.connect.commit()
            print('kgc data delete successfully!')
        except Exception as e:
            print('e= ', e)
            print('kgc data delete failed')

    def login_verify(self,KGCid, KGCpw):
        #login verify
        sql = "select `K_pw` from {} where `KGCid` = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (KGCid))
            password=self.cursor.fetchone()[0]
            print(KGCid,': ',password.decode())
            if password.decode() ==KGCpw:
                self.connect.commit()
                print("Login successful")
                return True
            else:
                print("Incorrect password!")
                return False            
        except Exception as e:
            print('e= ', e)
            print('Login verify failed')

    def show_kgc(self):
        #show all KGC
        sql = "select KGCid,Ti, Idi, Ri from {}".format(mysql_table)
        try:
            self.cursor.execute(sql)
            KGCdata=self.cursor.fetchone()
            while(KGCdata):
                print("KGC:",KGCdata[0]," Ti:",KGCdata[1],"Idi:",KGCdata[2],"Ri:",KGCdata[3])
                KGCdata=self.cursor.fetchone()
            
        except Exception as e:
            print('e= ', e)
            print('KGC data show failed')
            return 0

    def KGCdata_find(self,KGCid):
        #find the target KGC
        sql = "select Ti, Idi, Ri from {} where KGCid = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (KGCid))
            KGCdata=self.cursor.fetchone()
            if KGCdata:
                Ti=KGCdata[0]
                Idi=KGCdata[1]
                Ri=KGCdata[2]
                return [Ti,Idi,Ri]
            else:
                return 1
            
        except Exception as e:
            print('e= ', e)
            print('KGC finding failed')
            return 0

g_mysql=MYSQL()
def init():
    """
    初始化服务端
    """
    global g_socket_server
    g_socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    g_socket_server.bind(ADDRESS)
    g_socket_server.listen(6)  # 最大等待数
    print("KGCM start，wait for KGCs connecting...")

def accept_KGCclient():
    """
    接收新连接
    """
    while True:
        KGCclient, info = g_socket_server.accept()  # 阻塞，等待客户端连接
        # 给每个客户端创建一个独立的线程进行管理
        thread = Thread(target=message_handle, args=(KGCclient, info))
        # 设置成守护线程
        thread.setDaemon(True)
        thread.start()

def Register_handle(KGCclient,data):
    #register the KGC
    while(1):
        permission=input("agree or not: y/n \n")
        if permission == 'y' or 'Y':
            kgcm_list=['Y',b_str(kgcm.P_pub.export()),str(kgcm.nameId)]
            kgcm_data='!'.join(kgcm_list)
            print(kgcm_data)
            KGCclient.sendall(kgcm_data.encode(encoding='utf8'))
            break
        elif permission == 'n' or 'N':
            KGCclient.sendall("N!".encode(encoding='utf8'))
            break

def KGCpara_handle(KGCclient,data):
    #receive the KGC parameter
    global KGC_name
    KGC_name=data.split('!')[0]
    KGC_pw=data.split('!')[1]
    print(data.split('!')[2])
    KGC_Ti=EcPt.from_binary(str_b(data.split('!')[2]),kgcm.G)
    KGC_IDi=data.split('!')[3]
    print("KGC_Ti:",KGC_Ti)
    KGC_Ri,KGC_Ki=kgcm.partialKeyExtract(KGC_Ti,KGC_IDi)
    parical_keylist=[b_str(KGC_Ri.export()),str(KGC_Ki)]
    pkey_data='!'.join(parical_keylist)
    KGCclient.sendall(pkey_data.encode(encoding='utf8'))
    Ti=b_str(KGC_Ti.export())
    Ri=b_str(KGC_Ri.export())
    g_mysql.insert_kgc(KGC_name, KGC_pw, Ti, KGC_IDi, Ri)
    

def PkeyVerify_handle(KGCclient,KGCclient_type,data):
    #verify the partical key
    global KGC_name
    if data =='0':
        print("Partical key verify fail!\n")
        g_mysql.delete_kgc(KGC_name)
        
        remove_KGCclient(KGCclient_type)
    else:
        print("Partical key verify success!\n")
        global login_state
        login_state=1

def Authenticate_req_handle(KGCclient,data):
    #find the target KGC
    target_kgc=data
    
    Targetdata=g_mysql.KGCdata_find(target_kgc)
    if Targetdata == 1:
        senddata='0'
    else:
        senddata='!'.join(Targetdata)
    KGCclient.sendall(senddata.encode(encoding='utf8'))
    
def Login_handle(KGCclient,data):
    #login verify
    KGC_id=data.split('!')[0]
    KGC_pw=data.split('!')[1]
    Login_result=g_mysql.login_verify(KGC_id,KGC_pw)
    if Login_result:
        
        KGCclient.sendall('1'.encode(encoding='utf8'))
        global login_state
        login_state=1
    else:
        KGCclient.sendall('0'.encode(encoding='utf8'))

def message_handle(KGCclient, info):
    """
    消息处理
    """
    KGCclient.sendall("connect KGCM successfully!".encode(encoding='utf8'))
    while True:
        try:
            bytes = KGCclient.recv(1024)
            msg = bytes.decode(encoding='utf8')
            jd = json.loads(msg)
            cmd = jd['COMMAND']
            KGCclient_type = jd['Iclient_type']
            K_data=jd['data']
            if 'CONNECT' == cmd:
                g_conn_pool[KGCclient_type] = KGCclient
                print('on KGCclient connect: ' + KGCclient_type, info)
            elif 'R_0' == cmd:
                print('receive Login request: ' + KGCclient_type, K_data)
                Login_handle(KGCclient, K_data)
            elif 'R_1' == cmd:
                print('receive Register request: ' + KGCclient_type, K_data)
                Register_handle(KGCclient, K_data)
            elif 'R_2' == cmd:
                print('receive KGC parameter: ' + KGCclient_type, K_data)
                KGCpara_handle(KGCclient, K_data)
            elif 'R_3' == cmd:
                print('receive Partical key verify result ' + KGCclient_type, K_data)
                PkeyVerify_handle(KGCclient,KGCclient_type, K_data)
            elif 'R_4' == cmd:
                print('receive child KGC Authentication request: ' + KGCclient_type, K_data)
                Authenticate_req_handle(KGCclient, K_data)

        except Exception as e:
            print(e)
            time.sleep(30)
            remove_KGCclient(KGCclient_type)
            break

def remove_KGCclient(KGCclient_type):
    # 移除连接
    KGCclient = g_conn_pool[KGCclient_type]
    if None != KGCclient:
        KGCclient.close()
        g_conn_pool.pop(KGCclient_type)
        print("KGC client offline: " + KGCclient_type)

def Menu():
    # 主菜单
    while True:
        print("Select the operation:")
        print("1:Manage KGC Register")
        print("2: Show KGC")
        print("3: Remove KGC")
        print("4: Back to MENU")
        opr2=input("option: ")
        if opr2=='1':
            time.sleep(60)
            continue
        elif opr2=='2':
            g_mysql.show_kgc()
        elif opr2=='3':
            Kgcid=input("the KGC you want to remove: ")
            g_mysql.delete_kgc(Kgcid)
        elif opr2=='4':
            break
        else:
            print("please input the num 1~4!")

if __name__ == '__main__':
    init()
    # 新开一个线程，用于接收新连接
    thread = Thread(target=accept_KGCclient)
    thread.setDaemon(True)
    thread.start()
    # 主线程逻辑
    thread_menu = Thread(target=Menu)
    thread_menu.setDaemon(True)
    thread_menu.start()
    while True:
        time.sleep(0.1)
