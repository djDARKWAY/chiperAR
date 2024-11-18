import os
def logoPrint():
    # Limpeza do ecrâ e impressão do logótipo
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""\033[92m
         d8888 8888888b.  	      _______       __              ___    ____ 
        d88888 888   Y88b 	     / ____(_)___  / /_  ___  _____/   |  / __ \\
       d88P888 888    888 	    / /   / / __ \\/ __ \\/ _ \\/ ___/ /| | / /_/ / 
      d88P 888 888   d88P 	   / /___/ / /_/ / / / /  __/ /  / ___ |/ _, _/  
     d88P  888 8888888P"  	   \\____/_/ .___/_/ /_/\\___/_/  /_/  |_/_/ |_| 
    d88P   888 888 T88b   	         /_/                                   v4.0.2
   d8888888888 888  T88b  
  d88P     888 888   T88b     CipherAR: Application for Confidentiality and Integrity\033[0m
    """)
    print("--------------------------------------")