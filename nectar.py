# Libraries
import argparse
from honeypot import *
from web_honeypot import *


# Parse arguments

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  
  parser.add_argument("-a", '--address', type=str, required=True)
  parser.add_argument("-p", '--port', type=int, required=True)
  parser.add_argument('-u', '--username', type=str)
  parser.add_argument('-pw', '--password', type=str)
  
  
  parser.add_argument('-s', '--ssh', action='store_true')
  parser.add_argument('-w', '--web_server', action='store_true')
  
  args = parser.parse_args()
  
  try:
    if args.ssh:
      print("[-] Running SSH honeypot")
      honeypot(args.address, args.port, args.username, args.password, "ssh")
      
      if not args.username:
        username = None
      if not args.password:
        password = None
    elif args.web_server:
      print("[-] Running Web Server honeypot")
      
      if not args.username:
        args.username = "admin"
      if not args.password:
        args.password = "password"
      
      print(f'Port: {args.port} - Username: {args.username} - Password: {args.password}')
      
      # honeypot(args.address, args.port, args.username, args.password, "web_server")
      run_web_honeypot(args.port, args.username, args.password)
      
      pass
    else:
      print("[!] Please choose a honeypot to run: (SSH --ssh) or (Web Server --web_server)")
    
  except:
    print("\n Exiting NectarSentinel")
    
