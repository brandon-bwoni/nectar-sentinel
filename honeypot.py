#Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket 
import paramiko
import threading

# Constanst
logging_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

#host_key = 'server.key'
host_key = paramiko.RSAKey(filename='server.key')


# Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('/logs/audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('/logs/cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# Emulated Shell
def emulated_shell(channel, client_ip):
    channel.send(b'corporate-takura1$ ')  # Initial prompt
    command = b""
    while True:
        try:
            char = channel.recv(1)  
            if not char:  
                break

            channel.send(char)  

            if char in (b"\r", b"\n"):  
                
                command = command.strip()
                print(f"Received command: {command}, type: {type(command)}")
                if command == b"exit":
                    channel.send(b"Goodbye!\n")
                    break
                elif command == b"pwd":
                    response = b"/home/corpuser1\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"whoami":
                    response = b"corpuser1\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"ls":
                    response = b"takura1.conf\ndocuments\nsecrets\nscripts\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"cat takura1.conf":
                    response = b"Server config: Restricted access. Contact admin.\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"cat secrets":
                    response = b"Error: Permission denied\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"uname -a":
                    response = b"Linux corporate-server 5.15.0-1023-generic #29~20.04 SMP x86_64 GNU/Linux\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"df -h":
                    response = (
                        b"Filesystem      Size  Used Avail Use% Mounted on\n"
                        b"/dev/sda1       50G   20G   28G  42% /\n"
                        b"/dev/sdb1       100G  60G   40G  60% /data\n"
                    )
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"ps aux":
                    response = (
                        b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                        b"root         1  0.0  0.1  22568  1028 ?        Ss   10:00   0:02 /sbin/init\n"
                        b"corpuser1  345  0.0  0.2  23456  2048 pts/0    Ss   10:01   0:00 bash\n"
                    )
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command.startswith(b"ping"):
                    response = b"PING: Network unreachable\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"mkdir test_folder":
                    response = b"Directory 'test_folder' created\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"rm -rf /":
                    response = b"Error: Operation not permitted\n"
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"cat /etc/passwd":
                    response = (
                        b"root:x:0:0:root:/root:/bin/bash\n"
                        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                        b"corpuser1:x:1000:1000::/home/corpuser1:/bin/bash\n"
                    )
                    creds_logger.info(f'Command: {command.strip()}' + 'executed by: ' + client_ip)
                elif command == b"echo hello":
                    response = b"hello\n"
                    creds_logger.info(f'Command: {command.strip()}' + ' executed by: ' + client_ip)
                elif command == b"history":
                    response = (
                        b"1  pwd\n"
                        b"2  ls\n"
                        b"3  cat takura1.conf\n"
                        b"4  history\n"
                    )
                    creds_logger.info(f'Command: {command.strip()}' + ' executed by: ' + client_ip)
                else:
                    response = b"Command not found: " + command + b'\n'
                    creds_logger.info(f'Command: {command.strip()}' + ' executed by: ' + client_ip)


                # Send response and prompt
                channel.send(response)
                channel.send(b'corporate-takura1$ ')
                command = b""  
                
            else:
                command += char  

        except Exception as e:
            print(f"Error in shell: {e}")
            break

    channel.close()


# SSH Server + Sockets

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        
        
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
          
    
    def get_allowed_auths(self, username):
        return 'password'

      
      
    def check_auth_password(self, username, password):
        funnel_logger.info(f"Client {self.client_ip} attempted auth with username: {username}, password: {password}")
        creds_logger.info(f"{self.client_ip} ,{username} , {password}")
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
              return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
    
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
      
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
      
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
      

def client_handle(client, adr, username, password):
  client_ip = adr[0]
  print(f"{client_ip} has connected to the server")
  
  try:
    
    transport = paramiko.Transport(client)
    transport.local_version = SSH_BANNER
    server = Server(client_ip=client_ip, input_username=username, input_password=password)
    
    transport.add_server_key(host_key)
    
    transport.start_server(server=server)
    
    channel = transport.accept(100)  
    if channel is None:
        print("No channel was opened")
        transport.close()
        client.close()
        return
    
    standard_banner = "Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)!\r\n\r\n"
    channel.send(standard_banner)
    emulated_shell(channel, client_ip=client_ip)
  
  except Exception as error:
    print(f"Error: {error}")
    
    
  finally:
    try:
      transport.close()
    except Exception as error:
      print(f"Error: {error}")
    client.close()
    

# Provision SSH-based Honeypot
def honey_port(address, port, username, password):

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    
    socks.listen(100)
    print(f"SSH server is listening on port: {port}")
    
    while True:
        try:
          client, addr = socks.accept()
          ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
          ssh_honeypot_thread.start()
          
        
        except Exception as error:
          print(f"Error: {error}")

honey_port('127.0.0.1', 2223, 'username', 'password')





#ssh-keygen -t rsa -b 2048 -f server.key