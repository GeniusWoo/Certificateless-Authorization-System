import socket  
import json
import sys
import time
import pymysql
from petlib.ec import EcGroup
from petlib.bn import Bn
from petlib.ec import EcPt
from threading import Thread
from KGCM import *
from KGC import *
from user import *
from btostr import *
from public.hashfunctions import *

ADDRESS = ('127.0.0.1', 8712)
address_self = ('127.0.0.1', 8714)
target_addresslist=[('127.0.0.1', 8713), ('127.0.0.1', 8715), ('127.0.0.1', 8716)]
# 多个User客户端，这个Iclient_type设置不同的值，比如User1为Geniuswoo1，User2为Geniuswoo2
Iclient_type ='Geniuswoo2'
g_socket_server = None  # 负责监听的socket
KGCclient = socket.socket()  #socket for KGCM
global Iclient  #socket for User and KGC
global K_id
g_conn_pool = {}  # 连接池

mysql_host = '127.0.0.1'
mysql_db = 'CLPKC'
mysql_user = 'KGCstudio'
mysql_pwd = '1234'
mysql_table = 'User_table'

class MYSQL:
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
 
 
    def insert_user(self, USERid, USERpw, Ti, IDi, Ri):
        print("insert begin!\n")
        sql = "insert into {}(`ac_number`, `U_pw`,`KGCid`, `Ti`, `Idi`, `Ri`) VALUES (%s, %s, %s, %s, %s, %s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (USERid, USERpw, K_id, Ti, IDi, Ri))
            self.connect.commit()
            print('user data insert successfully!')
        except Exception as e:
            print('e= ', e)
            print('user data insert failed')

    def delete_user(self,USERid):
        sql = "delete from {} where ac_number = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (USERid))
            self.connect.commit()
            print('User data delete successfully!')
        except Exception as e:
            print('e= ', e)
            print('User data delete failed')

    def login_verify(self,USERid, USERpw):
        sql = "select `U_pw` from {} where `ac_number` = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (USERid))
            password=self.cursor.fetchone()[0]
            print(USERid,': ',password.decode())
            if password.decode() ==USERpw:
                self.connect.commit()
                print("Login successful")
                return True
            else:
                print("Incorrect password!")
                return False            
        except Exception as e:
            print('e= ', e)
            print('Login verify failed')

    def show_users(self):
        sql = "select ac_number,Ti, Idi, Ri from {} where `KGCid` = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql,(K_id))
            USERdata=self.cursor.fetchone()
            while(USERdata):
                print("USER:",USERdata[0]," Ti:",USERdata[1],"Idi:",USERdata[2],"Ri:",USERdata[3])
                USERdata=self.cursor.fetchone()
            
        except Exception as e:
            print('e= ', e)
            print('KGC data show failed')
            return 0

    def USERdata_find(self,USERid):
        sql = "select Ti, Idi, Ri from {} where ac_number = (%s)".format(mysql_table)
        try:
            self.cursor.execute(sql, (USERid))
            USERdata=self.cursor.fetchone()
            if USERdata:
                Ti=USERdata[0]
                Idi=USERdata[1]
                Ri=USERdata[2]
                return [Ti,Idi,Ri]
            else:
                return 1
            
        except Exception as e:
            print('e= ', e)
            print('Login verify failed')
            return 0

g_mysql=MYSQL()
def init():
    """
    初始化服务端
    """
    global g_socket_server
    g_socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    g_socket_server.bind(address_self)
    g_socket_server.listen(6)  # 最大等待数
    print("KGC ", Iclient_type ," start，wait for users connecting.../\n")

def accept_Iclient():
    """
    接收新连接
    """
    while True:
        global Iclient
        Iclient, info = g_socket_server.accept()  # 阻塞，等待客户端连接
        # 给每个客户端创建一个独立的线程进行管理
        thread = Thread(target=message_handle, args=(Iclient, info))  #Iclient is for the target kgci and useri
        # 设置成守护线程
        thread.setDaemon(True)
        thread.start()

def message_handle(Iclient, info):
    """
    消息处理
    """
    Iclient.sendall("connect KGC {} successfully!".format(K_id).encode(encoding='utf8'))
    while True:
        try:
            bytes = Iclient.recv(1024)
            msg = bytes.decode(encoding='utf8')
            jd = json.loads(msg)
            cmd = jd['COMMAND']
            Iclient_type = jd['Iclient_type']
            K_data=jd['data']
            if 'CONNECT' == cmd:
                g_conn_pool[Iclient_type] = Iclient
                print('on Iclient connect: ' + Iclient_type, info)
            elif 'R_A' == cmd:
                print('receive other KGC Authentication request: ' + Iclient_type, K_data)
                Authenticate_in_KGC(K_data, Iclient, Iclient_type)
            
            elif 'R_0' == cmd:
                print('receive Login request: ' + Iclient_type, K_data)
                Login_handle(Iclient, K_data)
            elif 'R_1' == cmd:
                print('receive Register request: ' + Iclient_type, K_data)
                Register_handle(Iclient, K_data)
            elif 'R_2' == cmd:
                print('receive User parameter: ' + Iclient_type, K_data)
                KGCpara_handle(Iclient, K_data)
            elif 'R_3' == cmd:
                print('receive Partical key verify result ' + Iclient_type, K_data)
                PkeyVerify_handle(Iclient,Iclient_type, K_data)
            elif 'R_4' == cmd:
                print('receive user Authentication request: ' + Iclient_type, K_data)
                Authenticate_req_handle(Iclient, K_data)
            
            
        except Exception as e:
            print(e)
            remove_Iclient(Iclient_type)
            break

def send_data(Uclient,cmd, data):
    global Iclient_type
    jd = {}
    jd['COMMAND'] = cmd
    jd['Iclient_type'] = Iclient_type
    jd['data'] = data
    
    jsonstr = json.dumps(jd)
    print('send: ' + jsonstr)
    Uclient.sendall(jsonstr.encode('utf8'))
    
def input_Iclient_type():
    return input("To connect KGCM, enter KGCclient name:")
    
def print_Menu():
    print("Input your request:\n")
    print("     1. New KGC register\n")
    print("     2. KGC login\n")
    print("     3. KGC parameters print\n")
    print("     4. KGC authentication\n")

def Register():
    global K_id
    K_id=input("Input your KGC id:\n")
    send_data(KGCclient, 'R_1', K_id)
    data=KGCclient.recv(1024).decode(encoding='utf8')
    print(data)
    if data.split('!')[0] == 'N':
        print("KGCM rufuse your registration.\n")
        KGCclient.close()
        sys.exit(0)
    elif data.split('!')[0] == 'Y':
        print("Your registration succeed!\n")
        global kgcm_P_pub
        global nameid_num
        global G
        nameid_num = int(data.split('!')[2])
        print("nameid: ",nameid_num)
        G = EcGroup(nameid_num)
        kgcm_P_pub = EcPt.from_binary(str_b(data.split('!')[1]),G)
        global kgci
        kgci = KGC(nameid_num, kgcm_P_pub)
        kgci.setSecretValue()
        password =  input("Input your password:\n")
        R2list = [K_id,password,b_str(kgci.Ti.export()),kgci.IDi]
        R2data='!'.join(R2list)
        send_data(KGCclient,"R_2",R2data)
        parical_key=KGCclient.recv(1024).decode(encoding='utf8')
        print("partical key: ",parical_key)
        p_isOK = kgci.setPrivateKey(EcPt.from_binary(str_b(parical_key.split('!')[0]),G),Bn.from_decimal(parical_key.split('!')[1]))
        if not p_isOK:
            print("The partical key from KGCM is illegal!\n")
            send_data(KGCclient, 'R_3','0')
            sys.exit(0)
        else:
            print("The partical key from KGCM is OK!\n")
            send_data(KGCclient, 'R_3','1')
            with open("./kgcdata/{}.txt".format(K_id),"w") as f:
                #save value: oP_pub ，nameID, Ri,ki, Ti, Idi,ti,si,d
                write_inList=[data.split('!')[1],data.split('!')[2],parical_key.split('!')[0],parical_key.split('!')[1],b_str(kgci.Ti.export()),kgci.IDi,str(kgci.ti),str(kgci.si),str(kgci.d)]    
                write_data='!'.join(write_inList)
                f.write(write_data) 
            return
    else:
        print(11111111)

def Login():
    global K_id
    K_id=input("Input your KGC id:\n")
    password=input("Input your password:\n")
    loginlist=[K_id, password]
    logindata='!'.join(loginlist)
    send_data(KGCclient, 'R_0', logindata)
    loginresult=KGCclient.recv(1024).decode(encoding='utf8')
    if loginresult == '1':
        print("\nLogin Success!")
        with open("./kgcdata/{}.txt".format(K_id), "r") as f:
            readdata=f.read()
        global kgcm_P_pub
        global nameid_num
        global G
        nameid_num = int(readdata.split('!')[1])
        print("nameid: ",nameid_num)
        G = EcGroup(nameid_num)
        kgcm_P_pub = EcPt.from_binary(str_b(readdata.split('!')[0]),G)
        global kgci
        kgci = KGC(nameid_num, kgcm_P_pub)
        kgci.Ri=EcPt.from_binary(str_b(readdata.split('!')[2]),G)
        kgci.ki=Bn.from_decimal(readdata.split('!')[3])
        kgci.Ti=EcPt.from_binary(str_b(readdata.split('!')[4]),G)
        kgci.IDi=readdata.split('!')[5]
        kgci.ti=Bn.from_decimal(readdata.split('!')[6])
        kgci.si=Bn.from_decimal(readdata.split('!')[7])
        kgci.d=Bn.from_decimal(readdata.split('!')[8])
        kgci.P_pub=kgci.P.pt_mul(kgci.d)
        return True
    elif loginresult == '0':
        print("\nLogin Fail!")
        return False

def Authenticate_in_KGC(rdata,Iclient,Iclienttype):
    pp_KGC=rdata.split('!')[1]
    print("Authentication for KGC {} starting...\n".format(pp_KGC))
    
    Ri_list = [EcPt.from_binary(str_b(rdata.split('!')[1]),G)]   
    Ti_list = [EcPt.from_binary(str_b(rdata.split('!')[2]),G)]
    IDi_list = [rdata.split('!')[3]]
    CT,verify_num1=kgci.gen_CT()
    print("\nverify_num1:",verify_num1)
    rk1,rk2=kgci.rekeygen(Ri_list,Ti_list,IDi_list) # KGC1 generate rekey rk1,rk2
    tok2list=[b_str(CT[0].export()),b_str(CT[1]),str(rk1),str(rk2)]
    tok2data='!'.join(tok2list)
    Iclient.sendall(tok2data.encode(encoding='utf8'))
    verify_num1i=Iclient.recv(1024).decode(encoding='utf8')
    if int(verify_num1i.strip(b'\x00'.decode())) == verify_num1:
        print("\nAuthentication Success!")
        Iclient.sendall('1'.encode(encoding='utf8'))
    else:
        print("\nAuthentication Fail!")
        Iclient.sendall('0'.encode(encoding='utf8'))

def Authenticate_to_KGC(target_address):
    print("Authentication start...")
    k_client = socket.socket()
    k_client.connect(target_address)
    send_data(k_client, 'CONNECT','1')
    print(k_client.recv(1024).decode(encoding='utf8'))
    sentlist=[K_id,b_str(kgci.Ri.export()),b_str(kgci.Ti.export()),kgci.IDi]
    sentdata='!'.join(sentlist)
    send_data(k_client,"R_A",sentdata)
    fk1data=k_client.recv(1024).decode(encoding='utf8')
    print(fk1data)
    CT1=(EcPt.from_binary(str_b(fk1data.split('!')[0]),G),str_b(fk1data.split('!')[1]))
    rk1=Bn.from_decimal(fk1data.split('!')[2])
    rk2=Bn.from_decimal(fk1data.split('!')[3])
    Ci1,Ci2=kgci.reencryption(CT1,rk1,rk2)
    verify_num1i = kgci.decryption2(CT1,Ci1,Ci2)
    k_client.sendall(str(verify_num1i).encode(encoding='utf8'))
    result=k_client.recv(1024).decode(encoding='utf8')
    if result == '1':
        print("\nAuthentication Success!")
    elif result == '0':
        print("\nAuthentication Fail!")
    k_client.close()

def Register_handle(Iclient,data):
    while(1):
        permission=input("agree or not: y/n \n")
        if permission == 'y' or 'Y':
            kgcm_list=['Y',b_str(kgci.P_pub.export()),str(kgci.nameId)]
            kgcm_data='!'.join(kgcm_list)
            print(kgcm_data)
            Iclient.sendall(kgcm_data.encode(encoding='utf8'))
            break
        elif permission == 'n' or 'N':
            Iclient.sendall("N!".encode(encoding='utf8'))
            break

def KGCpara_handle(Iclient,data):
    global User_name
    User_name=data.split('!')[0]
    User_pw=data.split('!')[1]
    print(data.split('!')[2])
    USER_Ti=EcPt.from_binary(str_b(data.split('!')[2]),kgci.G)
    USER_IDi=data.split('!')[3]
    print("KGC_Ti:",USER_Ti)
    USER_Ri,USER_Ki=kgci.partialKeyExtract(USER_Ti,USER_IDi)
    parical_keylist=[b_str(USER_Ri.export()),str(USER_Ki)]
    pkey_data='!'.join(parical_keylist)
    Iclient.sendall(pkey_data.encode(encoding='utf8'))
    Ti=b_str(USER_Ti.export())
    Ri=b_str(USER_Ri.export())
    g_mysql.insert_user(User_name, User_pw,Ti, USER_IDi, Ri)
    

def PkeyVerify_handle(Iclient,Iclient_type,data):
    global User_name
    if data =='0':
        print("Partical key verify fail!\n")
        g_mysql.delete_kgc(User_name)
        
        remove_Iclient(Iclient_type)
    else:
        print("Partical key verify success!\n")
        global login_state
        login_state=1

def Authenticate_req_handle(Iclient,data):
    target_user=data
    
    Targetdata=g_mysql.KGCdata_find(target_user)
    if Targetdata == 1:
        senddata='0'
    else:
        senddata='!'.join(Targetdata)
    Iclient.sendall(senddata.encode(encoding='utf8'))
    
def Login_handle(Iclient,data):
    KGC_id=data.split('!')[0]
    KGC_pw=data.split('!')[1]
    Login_result=g_mysql.login_verify(KGC_id,KGC_pw)
    if Login_result:
        
        Iclient.sendall('1'.encode(encoding='utf8'))
        global login_state
        login_state=1
    else:
        Iclient.sendall('0'.encode(encoding='utf8'))

def remove_Iclient(client_type):
    Iclient = g_conn_pool[client_type]
    if None != Iclient:
        Iclient.close()
        g_conn_pool.pop(client_type)
        print("client offline: " + client_type)

def Menu():
    while True:
        time.sleep(0.1)
        print("Select the operation:")
        print("1: Register")
        print("2: Login")
        opr=input("option: ")
        if opr == '1':
            Register()
            break
        elif opr == '2':
            if Login():
                break
            else:
                print("Your password is not write!")
                continue
        else:
            print("please input 1 or 2! ")
            continue
    while True:
        time.sleep(0.1)
        print("Select the operation:")
        print("1: Authenticate with other KGCs")
        print("2: Manage Users")
        opr1=input("option: ")
        if opr1 == '1':
            while True:
                time.sleep(0.1)
                target_KGC=input("Input the target KGC num 1~3:\n or input 4 back to MENU")
                if target_KGC=='1':
                    Authenticate_to_KGC(target_addresslist[0])
                elif target_KGC=='2':
                    Authenticate_to_KGC(target_addresslist[1])
                elif target_KGC=='3':
                    Authenticate_to_KGC(target_addresslist[2])
                elif target_KGC=='4':
                    break
                else:
                    print("please input the num 1~4!")
        elif opr1 == '2':
            print("Select the operation:")
            print("1:Manage users Register")
            print("2: Show users")
            print("3: Remove User")
            print("4: Back to MENU")
            opr2=input("option: ")
            if opr2=='1':
                time.sleep(60)
                continue
            elif opr2=='2':
                g_mysql.show_users()
            elif opr2=='3':
                userid=input("the User you want to remove: ")
                g_mysql.delete_user(userid)
            elif opr2=='4':
                break
            else:
                print("please input the num 1~4!")
            continue
    

if '__main__' == __name__:
    init()
    # 新开一个线程，用于接收新连接
    KGCclient.connect(ADDRESS)
    thread = Thread(target=accept_Iclient)
    thread.setDaemon(True)
    thread.start()
    print(KGCclient.recv(1024).decode(encoding='utf8'))
    send_data(KGCclient, 'CONNECT','1')
    thread_menu = Thread(target=Menu)
    thread_menu.setDaemon(True)
    thread_menu.start()
    while True:
        time.sleep(0.1)
    
   
        