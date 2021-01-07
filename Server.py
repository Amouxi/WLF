#!/usr/bin/python3
import socket,datetime
import sys,os
import threading
import time
from queue import Queue
import select

NUMBER_OF_THREADS = 3
JOB_NUMBER = [1, 2, 3]
queue = Queue()
heartbeat_counter = []
all_connections = [] # contains all socket connections connections
all_address = [] # Contains all ip adresses
log=open("log.txt",'a')


class RepeatedTimer(object):
	def __init__(self, duration, function):
		self._duration=duration # the Duration of the Timer
		self._function=function
		#  Lock to prevent replacing timer
		self._timer_lock=Lock()
		# none Means timer is not defined
		self._timer = None
		
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
# Create a Socket ( connect two computers)
def create_socket():
    try:
        global host
        global port
        global s
        host = sys.argv[1]
        port = int(sys.argv[2])
        s = socket.socket()

    except socket.error as msg:
        print("Socket creation error: " + str(msg))


# Binding the socket and listening for connections
def bind_socket():
    try:
        global host
        global port
        global s
        print("Binding the Port: " + str(port))

        s.bind((host, port))
        s.listen(5)

    except socket.error as msg:
        print("Socket Binding error" + str(msg) + "\n" + "Retrying...")
        bind_socket()


# Establish connection with a client (socket must be listening)

def socket_accept():
    conn, address = s.accept()
    print("Connection has been established! | " + " IP " + address[0] + " | Port" + str(address[1]))
    send_commands(conn)
    conn.close()


# Send commands to client
def send_target_commands(conn):
	while True:
		try:
			cmd = input()
			if cmd == 'quit':
				break
			if len(str.encode(cmd)) > 0:
				conn.send(str.encode(cmd))
		except:
			print("Error sending commands")
			break


def accepting_connections():
    for c in all_connections:
        c.close()
    del all_connections[:]
    del all_address[:]

    while True:
        try:
            conn, address = s.accept()
            s.setblocking(1)  # Prevents timeouts

            all_connections.append(conn)
            all_address.append(address)

            print("Connecting has been established" + address[0])
        except:
            print("ERROR: accepting connection")


def start_terminal():
	while True:
		cmd = input("terminal> ")
		if cmd == 'list':
			list_connections()
		elif cmd=="blupdate":
			for i,conn in enumerate(all_connections):
				conn.send(b"blupdate")
				print("[!!] Updated "+all_address[i][0])
		elif 'select' in cmd:
			conn=connect_Client(cmd)
			if conn is not None:
				send_target_commands(conn)
		else:
			print("Command not recognized")
			
def connect_Client(cmd):
	try:
		target=cmd.replace("select","")
		target=int(target)
		conn=all_connections[target]
		print("You're now connected to: "+str(all_address[target][0]))
		print(str(all_address[target][0]) + ">",end="")
		return conn
	except:
		print("Selection is not valid")

def list_connections():
    results = ''
    
    for i, conn in enumerate(all_connections):
        try:
            conn.send(b"1")
            conn.recv(1048)
        except:
            del all_connections[i]
            del all_address[i]
            continue

        results += str(i) + " " + str(all_address[i][0]) +" "+ str(all_address[i][1]) + "\n"
    print("----CLIENTS-----" + "\n" + results)

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
		if x == 1: # Thread for starting the server and accepting connections from Clients
			create_socket()
			bind_socket()
			accepting_connections()
		if x == 2: # Thread for listening for clients commands
			start_listening()
		if x==3:
			start_terminal() # Thread for Server Terminal
		queue.task_done()

# Listener for Client requests.

def start_listening():
	while True:
		for i,conn in enumerate(all_connections):
			ready=select.select([conn],[],[],0.05)
			if ready[0]:
				# Windows Throws an error when disconnecting from server
				try:
					data=conn.recv(1024)	
					# Linux Sends empty Data when disconnecting.	
					if len(data.decode()) == 0:
						print(f"[?] {all_address[i][0]} has disconnected from server at "+str(datetime.datetime.now())+"\n")
						log.write(f"[?] {all_address[i][0]} has disconnected from server at "+str(datetime.datetime.now())+" \n")
						log.flush()
						del all_connections[i]
						del all_address[i]
						pass
						
					else:
						# 011 - Client entered BlackListed site
						# 001 - Client under MiTM attack
						
						if "011" in data.decode():
							print(f"[!] {all_address[i][0]} Entered a blacklisted site\n")
							log.write(f"[!] {all_address[i][0]} Entered a blacklisted site \n")
							log.flush()
						
						elif "001" in data.decode():
							print(f"[!] {all_address[i][0]} is under MiTM attack!\n")
							log.write(f"[!] {all_address[i][0]} is under MiTM attack!\n")
							log.flush()
						else:  # Listen for Client Terminal response
							print(all_address[i][0]+"> "+data.decode())
							
				except:
					# Remove Disconnected windows machine
						print(f"[?] {all_address[i][0]} has disconnected from server at "+str(datetime.datetime.now()))
						log.write(f"[?] {all_address[i][0]} has disconnected from server at "+str(datetime.datetime.now())+" \n")
						log.flush()
						del all_connections[i]
						del all_address[i]
						pass
# main()

create_workers()
create_jobs()
