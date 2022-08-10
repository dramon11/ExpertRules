
#Author : Dramon11
#email : dramon11@gmail.com

import hashlib
import os
import re

lesta = []
lesta2 = []
nombres = open("C:\\01\\ABA-220003.txt", "r", encoding='utf-8')
while(True):
    linea = nombres.readline()
	      
    if not linea:
     break
    N = linea.strip()	
    if (N[0:4]) == "Hash":
     h1 ="" 
     N1 = (N[5:69]).encode() 
     A1 = hashlib.md5(N1).hexdigest()
     U1 = str(A1) #+"\n"
     lesta.append(U1)
         
     archivo = open("C:\\01\\hashs.txt", "w")
     erc = "EXECUTE READ CREATE"
     print("Rule {", file=archivo)
     print("\t"+"Process {", file=archivo)
     print("\t"+"\t"+"Include OBJECT_NAME {", file=archivo)
     print("\t"+"\t"+"\t"+"-v *", file=archivo)
     print("\t"+"\t"+"}", file=archivo)
     print("\t"+"}", file=archivo)
     print("\t"+"Target {", file=archivo)
     print("\t"+"\t"+"Match FILE {", file=archivo)
     print("\t"+"\t"+"\t"+"Include MD5 {", file=archivo)
	 
     for hash in lesta:
      print("\t"+"\t"+"\t"+"\t"+"-v "+f'"{hash}"', file=archivo)
     print("\t"+"\t"+"\t"+"}", file=archivo)
     print("\t"+"\t"+"\t"+"Include -access "+f'"{erc}"', file=archivo)
     print("\t"+"\t"+"}", file=archivo)
     print("\t"+"}", file=archivo)
     print("}", file=archivo)
     archivo.close()
    else:
     if (N[0:4]) == "File":
      N2 = (N[9:80]) 
      #N5 = f'"{N2}"'
      lesta2.append(N2)
      archivo2 = open("C:\\01\\filespath.txt", "w")
      erc = "EXECUTE READ CREATE"
      print("Rule {", file=archivo2)
      print("\t"+"Process {", file=archivo2)
      print("\t"+"\t"+"Include OBJECT_NAME {", file=archivo2)
      print("\t"+"\t"+"\t"+"-v *", file=archivo2)
      print("\t"+"\t"+"}", file=archivo2)
      print("\t"+"}", file=archivo2)
      print("\t"+"Target {", file=archivo2)
      print("\t"+"\t"+"Match FILE {", file=archivo2)
      print("\t"+"\t"+"\t"+"Include OBJECT_NAME {", file=archivo2)
	 
      for rutas in lesta2:
       print("\t"+"\t"+"\t"+"\t"+"-v "+f'"{rutas}"', file=archivo2)
      print("\t"+"\t"+"\t"+"}", file=archivo2)
      print("\t"+"\t"+"\t"+"Include -access "+f'"{erc}"', file=archivo2)
      print("\t"+"\t"+"}", file=archivo2)
      print("\t"+"}", file=archivo2)
      print("}", file=archivo2)
      archivo2.close()



