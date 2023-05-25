# the keygen might take a few seconds to produce a key
import random
import string

print "It might take a few seconds to produce a key"
chars =  string.ascii_letters.lower() #lower cases produces faster results based on multiple tries of multiple set of characters


while (1):
    
    #one thing to keep in mind if you tried to find a key that meet the two conditions (first part and second part of the algorithm) simultaneously it will take a huge amount of time 
    #what i mean by that is finding one key that passes the first part of the algorithm and hope that same key will pass the second part of the algorithm as well
    #one trick for solving this problem is trying to find a key that passes one of the algorithms and after that we will keep the characters that passed the first part
    # and we will try to find the proper characters to pass the second algorithm as well
    
    
    #here i will try to find a key that will pass the second part of the algorithm first
    key=''.join(random.choice(chars) for x in range(16))
   
    val =((ord(key[13])-ord(key[14])+2)*(ord(key[1]) - 4 - ord(key[3]) ) * (ord(key[12]) - 5 - ord(key[2]))*0x88 + (ord(key[1]) - ord(key[2])) * (ord(key[1]) - ord(key[2])))
        
    if val == -36992 : # -36992 = 0xFFFF6F80 
        
        part1 = key[1:4]   # 
                           #  we will keep the characters that passed the second part of the algorithm 
        part2 = key [12:15]#
        
        for i in range (500): #the reason for using a for loop is that sometimes a key that passes the second algo could take a significant amount of time
                              #to pass the first one hence the need to get a new key 
            
            # at this point we know that we have the characters that will pass the second part of the algorithm
            # now we will  try to find characters used only by the first part of the algorithm namely characters at index 6,8 and 15 
            
            mk=''.join(random.choice(chars) for x in range(8))
            
            last_c =''.join(random.choice(chars) for x in range(1)) 
           
            key=key[0]+part1+mk+part2+last_c 
      
            val2 = (ord(key[12]) - ord(key[3]))*(ord(key[6])-ord(key[3]))  * (ord(key[8])-ord(key[12]))*4 +  (ord(key[13])-ord(key[15]))*(ord(key[13])-ord(key[15]))
            
            if  val2 == 0x11B8:
            
                print key
                quit()
        
