import time
from threading import Thread
def Menu():
    while True:
        time.sleep(0.1)
        print("Select the operation:")
        print("1: Register")
        print("2: Login")
        opr=input("option: ")
        if opr == '1':
            print("111")
            break
        elif opr == '2':
            
            print("Your password is not write!")
            continue
        else:
            print("please input 1 or 2! ")
            continue

thread_menu = Thread(target=Menu)
#thread_menu.setDaemon(True)
thread_menu.start()