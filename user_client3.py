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

ADDRESS = ('127.0.0.1', 8714)
address_self = ('127.0.0.1', 8717)
target_addresslist=[('127.0.0.1', 8715), ('127.0.0.1', 8716), ('127.0.0.1', 8718)]
Iclient_type ='Wwoo3'
g_socket_server = None  # 负责监听的socket
USERclient = socket.socket()  #socket for USERM
global Iclient  #socket for User and USER
global U_id
g_conn_pool = {}  # 连接池

def init():
    """
    初始化服务端
    """
    global g_socket_server
    g_socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    g_socket_server.bind(address_self)
    g_socket_server.listen(6)  # 最大等待数
    print("USER ", Iclient_type ," start，wait for users connecting.../\n")

def accept_Iclient():
    """
    接收新连接
    """
    while True:
        global Iclient
        Iclient, info = g_socket_server.accept()  # 阻塞，等待客户端连接
        # 给每个客户端创建一个独立的线程进行管理
        thread = Thread(target=message_handle, args=(Iclient, info))  #Iclient is for the target useri and useri
        # 设置成守护线程
        thread.setDaemon(True)
        thread.start()

def message_handle(Iclient, info):
    """
    消息处理
    """
    Iclient.sendall("connect User {} successfully!".format(U_id).encode(encoding='utf8'))
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
                print('on USERclient connect: ' + Iclient_type, info)
            elif 'R_A' == cmd:
                print('receive other USER Authentication request: ' + Iclient_type, K_data)
                Authenticate_in_USER(K_data, Iclient, Iclient_type)
            
            
        except Exception as e:
            print(e)
            remove_Iclient(Iclient_type)
            break

def send_data(USERclient,cmd, data):
    global Iclient_type
    jd = {}
    jd['COMMAND'] = cmd
    jd['Iclient_type'] = Iclient_type
    jd['data'] = data
    
    jsonstr = json.dumps(jd)
    print('send: ' + jsonstr)
    USERclient.sendall(jsonstr.encode('utf8'))
    
def input_Iclient_type():
    return input("To connect USERM, enter USERclient name:")
    
def print_Menu():
    print("Input your request:\n")
    print("     1. New USER register\n")
    print("     2. USER login\n")
    print("     3. USER parameters print\n")
    print("     4. USER authentication\n")

def Register():
    global U_id
    U_id=input("Input your USER id:\n")
    send_data(USERclient, 'R_1', U_id)
    data=USERclient.recv(1024).decode(encoding='utf8')
    print(data)
    if data.split('!')[0] == 'N':
        print("USERM rufuse your registration.\n")
        USERclient.close()
        sys.exit(0)
    elif data.split('!')[0] == 'Y':
        print("Your registration succeed!\n")
        global userm_P_pub
        global nameid_num
        global G
        nameid_num = int(data.split('!')[2])
        print("nameid: ",nameid_num)
        G = EcGroup(nameid_num)
        userm_P_pub = EcPt.from_binary(str_b(data.split('!')[1]),G)
        global useri
        useri = User(nameid_num, userm_P_pub)
        useri.setSecretValue()
        password =  input("Input your password:\n")
        R2list = [U_id,password,b_str(useri.Ti.export()),useri.IDi]
        R2data='!'.join(R2list)
        send_data(USERclient,"R_2",R2data)
        parical_key=USERclient.recv(1024).decode(encoding='utf8')
        print("partical key: ",parical_key)
        p_isOK = useri.setPrivateKey(EcPt.from_binary(str_b(parical_key.split('!')[0]),G),Bn.from_decimal(parical_key.split('!')[1]))
        if not p_isOK:
            print("The partical key from KGC is illegal!\n")
            send_data(USERclient, 'R_3','0')
            sys.exit(0)
        else:
            print("The partical key from KGC is OK!\n")
            send_data(USERclient, 'R_3','1')
            with open("./userdata/{}.txt".format(U_id),"w") as f:
                #save value: P_pub ，nameID, Ri,ki, Ti, Idi,ti,si
                write_inList=[data.split('!')[1],data.split('!')[2],parical_key.split('!')[0],parical_key.split('!')[1],b_str(useri.Ti.export()),useri.IDi,str(useri.ti),str(useri.si)]    
                write_data='!'.join(write_inList)
                f.write(write_data) 
            return
    else:
        print(11111111)

def Login():
    global U_id
    U_id=input("Input your USER id:\n")
    password=input("Input your password:\n")
    loginlist=[U_id, password]
    logindata='!'.join(loginlist)
    send_data(USERclient, 'R_0', logindata)
    loginresult=USERclient.recv(1024).decode(encoding='utf8')
    if loginresult == '1':
        print("\nLogin Success!")
        with open("./userdata/{}.txt".format(U_id), "r") as f:
            readdata=f.read()
        global userm_P_pub
        global nameid_num
        global G
        nameid_num = int(readdata.split('!')[1])
        print("nameid: ",nameid_num)
        G = EcGroup(nameid_num)
        userm_P_pub = EcPt.from_binary(str_b(readdata.split('!')[0]),G)
        global useri
        useri = User(nameid_num, userm_P_pub)
        useri.Ri=EcPt.from_binary(str_b(readdata.split('!')[2]),G)
        useri.ki=Bn.from_decimal(readdata.split('!')[3])
        useri.Ti=EcPt.from_binary(str_b(readdata.split('!')[4]),G)
        useri.IDi=readdata.split('!')[5]
        useri.ti=Bn.from_decimal(readdata.split('!')[6])
        useri.si=Bn.from_decimal(readdata.split('!')[7])
        return True
    elif loginresult == '0':
        print("\nLogin Fail!")
        return False

def Authenticate_in_USER(rdata,Iclient,Iclienttype):
    pp_KGC=rdata.split('!')[1]
    print("Authentication for USER {} starting...\n".format(pp_KGC))
    
    Ri_list = [EcPt.from_binary(str_b(rdata.split('!')[1]),G)]   
    Ti_list = [EcPt.from_binary(str_b(rdata.split('!')[2]),G)]
    IDi_list = [rdata.split('!')[3]]
    CT,verify_num1=useri.gen_CT()
    print("\nverify_num1:",verify_num1)
    rk1,rk2=useri.rekeygen(Ri_list,Ti_list,IDi_list) # User generate rekey rk1,rk2
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

def Authenticate_to_USER(target_address):
    print("Authentication start...")
    k_client = socket.socket()
    k_client.connect(target_address)
    send_data(k_client, 'CONNECT','1')
    print(k_client.recv(1024).decode(encoding='utf8'))
    sentlist=[U_id,b_str(useri.Ri.export()),b_str(useri.Ti.export()),useri.IDi]
    sentdata='!'.join(sentlist)
    send_data(k_client,"R_A",sentdata)
    fk1data=k_client.recv(1024).decode(encoding='utf8')
    print(fk1data)
    CT1=(EcPt.from_binary(str_b(fk1data.split('!')[0]),G),str_b(fk1data.split('!')[1]))
    rk1=Bn.from_decimal(fk1data.split('!')[2])
    rk2=Bn.from_decimal(fk1data.split('!')[3])
    Ci1,Ci2=useri.reencryption(CT1,rk1,rk2)
    verify_num1i = useri.decryption2(CT1,Ci1,Ci2)
    k_client.sendall(str(verify_num1i).encode(encoding='utf8'))
    result=k_client.recv(1024).decode(encoding='utf8')
    if result == '1':
        print("\nAuthentication Success!")
    elif result == '0':
        print("\nAuthentication Fail!")
    k_client.close()

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
        target_USER=input("Input the target USER num 1~3:\n")
        if target_USER=='1':
            Authenticate_to_USER(target_addresslist[0])
        elif target_USER=='2':
            Authenticate_to_USER(target_addresslist[1])
        elif target_USER=='3':
            Authenticate_to_USER(target_addresslist[2])
        else:
            print("please input the num 1~3!")

if '__main__' == __name__:
    init()
    # 新开一个线程，用于接收新连接
    USERclient.connect(ADDRESS)
    thread = Thread(target=accept_Iclient)
    thread.setDaemon(True)
    thread.start()
    print(USERclient.recv(1024).decode(encoding='utf8'))
    send_data(USERclient, 'CONNECT','1')
    thread_menu = Thread(target=Menu)
    thread_menu.start()
    
   
        