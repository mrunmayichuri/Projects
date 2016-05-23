#!/usr/bin/env python
#Mrunmayi Churi
#Password Man

import sys, struct, string, select
import os
from Crypto.Cipher import AES
import base64
from Crypto import Random
from argparse import OPTIONAL
import Crypto.Util.Counter
from Crypto.Util import Counter

#Function to read the username-password pair from the database
def read_pass():
    read_flag_ecb = 0
    read_flag_ctr = 0
    read_flag_cbc = 0
    uname_flag_ecb = 0
    uname_flag_ctr = 0
    uname_flag_cbc = 0
    uname = raw_input("Enter the username for which information is required:\n")
    with open('./ecb_file.txt','r') as ecb_file:
        if os.stat('./ecb_file.txt').st_size == 0:	#Checking if the database file is empty
            read_flag_ecb = 1
        else:
            for line in ecb_file:
                u = line.split(' ')
                try:
                    if u[0] == uname:
                        uname_flag_ecb = 1
                        cipher_text = u[1].strip()
                        plain_text = ecb_decryption(cipher_text)
                        print "Password: " + plain_text
                        print "Mode: ECB\n"
                except ValueError:
                    pass

    with open('./ctr_file.txt','r') as ctr_file:
        if os.stat('./ctr_file.txt').st_size == 0:	#Checking if the database file is empty
            read_flag_ctr = 1
        else:
            for line in ctr_file:
                u = line.split(' ')
                try:               
                    if u[0] == uname:
                        uname_flag_ctr = 1
                        cipher_text = u[1].strip()
                        plain_text = ctr_decryption(cipher_text)
                        print "Password: " + plain_text
                        print "Mode: CTR\n"
                except ValueError:
                    pass

    with open('./cbc_file.txt','r') as cbc_file:
        if os.stat('./cbc_file.txt').st_size == 0:	#Checking if the database file is empty
            read_flag_cbc = 1           
        else:
            for line in cbc_file:
                u = line.split(' ')
                try:
                    if u[0] == uname:
                        uname_flag_cbc = 1
                        cipher_text = u[1].strip()
                        plain_text = cbc_decryption(cipher_text)
                        print "Password: " + plain_text
                        print "Mode: CBC\n"
                except ValueError:
                    pass
    if read_flag_ecb == 1 and read_flag_ctr == 1 and read_flag_cbc == 1:
        print "Cannot read! Password files are empty!\n"
    elif uname_flag_ecb == 1 or uname_flag_ctr == 1 or uname_flag_cbc == 1:
        pass
    else:
        print "Username does not exist!\n"

#Function to obtain user input, check if the username-password pair exists, if not, then write the username-password pair to the database
def write_pass():
    exist_ecb = 0
    exist_ctr = 0
    exist_cbc = 0
    exist_ecb_uname = 0
    exist_ctr_uname = 0
    exist_cbc_uname = 0
    flag = 0
    uname = raw_input("Enter the username: ")
    
    while not uname:
        print "Empty username! Kindly enter the username again: "	#Checking if the user entered an empty username
        uname = raw_input()
    else:
        pword = raw_input("Enter the password: ")
        pword = password_check(pword)						#Checking the length of the password
        select = raw_input("Enter the mode:\n 1. ECB\n 2. CTR\n 3. CBC\nYour input: ")
        with open('./ecb_file.txt', 'r+') as ecb_file, open('./ctr_file.txt', 'r+') as ctr_file, open('./cbc_file.txt', 'r+') as cbc_file:
          
            for line in ecb_file:
                cipher_text = ecb_encryption(pword)
                u = line.split(' ')
                if u[0] == uname:
                    exist_ecb_uname = 1
                    plain = u[1].strip()
                    new_plain = plain.rstrip(" ")
                    plain_text = ecb_decryption(new_plain)
                    plain_text = plain_text.rstrip(" ")
                    if u[0] == uname and plain_text == pword:
                        exist_ecb = 1                   
       
            for line in ctr_file:
                cipher_text = ctr_encryption(pword)
                u = line.split(' ')                              
                if u[0] == uname:
                    exist_ctr_uname = 1
                    plain = u[1].strip()
                    new_plain = plain.rstrip(" ")
                    plain_text = ctr_decryption(new_plain)
                    plain_text = plain_text.rstrip(" ")
                    if u[0] == uname and plain_text == pword:
                        exist_ctr = 1 
                       
            for line in cbc_file:
                cipher_text = cbc_encryption(pword)
                u = line.split(' ')                
                if u[0] == uname:
                    exist_cbc_uname = 1
                    plain = u[1].strip()
                    new_plain = plain.rstrip(" ")
                    plain_text = cbc_decryption(new_plain)
                    plain_text = plain_text.rstrip(" ")
                    if u[0] == uname and plain_text == pword:
                        exist_cbc = 1
            
            while not select:
                print "Invalid option. Please enter the correct mode: "
                select = raw_input()
            else:
                if exist_ecb == 1 or exist_ctr == 1 or exist_cbc == 1:	#Flags to check if the username-password pair exists in the database
                    flag = 1		
                    print "This Username and Password pair already exists!"
                    new_pass_input = raw_input("Do you want to enter a new password for this Username? 1. YES  2. NO\nYour input: ")
                    if new_pass_input == '1':
                        pword = raw_input("Enter the new password: ")
                        pword = password_check(pword)
                        if select == '1':
                            delete_ctr(uname)
                            delete_cbc(uname)
                            cipher_text = ecb_encryption(pword)
                            replace_password_ecb(uname , cipher_text)
                        elif select == '2':
                            delete_ecb(uname)
                            delete_cbc(uname)
                            cipher_text = ctr_encryption(pword)
                            replace_password_ctr(uname , cipher_text)
                        else:
                            delete_ecb(uname)
                            delete_ctr(uname)
                            cipher_text = cbc_encryption(pword)
                            replace_password_cbc(uname , cipher_text)
                elif exist_ecb_uname == 1 or exist_ctr_uname == 1 or exist_cbc_uname == 1: #Flags to check if the username exists in the database
                    if flag == 1:
                        pass
                    else:    
                        print "This Username already exists!\n"
                        new_pass_input = raw_input("Do you want to enter a new password for this Username? 1. YES  2. NO\nYour input: ")
                        if new_pass_input == '1':
                            pword = raw_input("Enter the new password: ")
                            pword = password_check(pword)
                            if select == '1':
                                delete_ctr(uname)
                                delete_cbc(uname)
                                cipher_text = ecb_encryption(pword)
                                replace_password_ecb(uname , cipher_text)
                            elif select == '2':
                                delete_ecb(uname)
                                delete_cbc(uname)
                                cipher_text = ctr_encryption(pword)
                                replace_password_ctr(uname , cipher_text)
                            else:
                                delete_ecb(uname)
                                delete_ctr(uname)
                                cipher_text = cbc_encryption(pword)
                                replace_password_cbc(uname , cipher_text)
                        else:
                            pass
                
                else:
                    if select == '1': 
                        write_to_file_ecb(uname,pword)                 
                    elif select == '2':
                        write_to_file_ctr(uname,pword)
                    else:
                        write_to_file_cbc(uname,pword)

#Password security - checking the length of the password                      
def password_check(pword):
    length = len(pword)
    if length < 8:
        password = raw_input("Password length should be greater than or equal to 8. Please enter a new password: ")
    else:
        password = pword
    return password

#Functions to write the username-password pair to the database
def write_to_file_ecb(uname, pword):
    cipher_text = ecb_encryption(pword)
    with open('./ecb_file.txt', 'a') as w_ecb_file:
        w_ecb_file.write(uname)
        w_ecb_file.write(" ")
        w_ecb_file.write(cipher_text)
        w_ecb_file.write("\n")

def write_to_file_ctr(uname, pword):
    cipher_text = ctr_encryption(pword)
    with open('./ctr_file.txt', 'a') as w_ctr_file:
        w_ctr_file.write(uname)
        w_ctr_file.write(" ")
        w_ctr_file.write(cipher_text)
        w_ctr_file.write("\n")

def write_to_file_cbc(uname, pword):
    cipher_text = cbc_encryption(pword)
    with open('./cbc_file.txt', 'a') as w_cbc_file:
        w_cbc_file.write(uname)
        w_cbc_file.write(" ")
        w_cbc_file.write(cipher_text)
        w_cbc_file.write("\n")

#Functions to delete a username-password pair in the database
def delete_ecb(uname):
    temporary = []
    with open('./ecb_file.txt', 'r') as r_ecb_file:
        for line in r_ecb_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./ecb_file.txt', 'w') as w_ecb_file:
        w_ecb_file.writelines(temporary)

def delete_ctr(uname):
    temporary = []
    with open('./ctr_file.txt', 'r') as r_ctr_file:
        for line in r_ctr_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./ctr_file.txt', 'w') as w_ctr_file:
        w_ctr_file.writelines(temporary)

def delete_cbc(uname):
    temporary = []
    with open('./cbc_file.txt', 'r') as r_cbc_file:
        for line in r_cbc_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./cbc_file.txt', 'w') as w_cbc_file:
        w_cbc_file.writelines(temporary)

#Functions to replace the password in the database
def replace_password_ecb(uname , cipher_text):
    temporary = []
    with open('./ecb_file.txt', 'r') as r_ecb_file:
        for line in r_ecb_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./ecb_file.txt', 'w') as w_ecb_file:
        w_ecb_file.writelines(temporary)
        w_ecb_file.write(uname)
        w_ecb_file.write(" ")
        w_ecb_file.write(cipher_text)
                
                
def replace_password_ctr(uname , cipher_text):
    temporary = []
    with open('./ctr_file.txt', 'r') as r_ctr_file:
        for line in r_ctr_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./ctr_file.txt', 'w') as w_ctr_file:
        w_ctr_file.writelines(temporary)
        w_ctr_file.write(uname)
        w_ctr_file.write(" ")
        w_ctr_file.write(cipher_text)

def replace_password_cbc(uname , cipher_text):    
    temporary = []
    with open('./cbc_file.txt', 'r') as r_cbc_file:
        for line in r_cbc_file:
            u = line.split(' ')
            if u[0] == uname:
                continue
            else:
                temporary.append(line)
    with open('./cbc_file.txt', 'w') as w_cbc_file:
        w_cbc_file.writelines(temporary)
        w_cbc_file.write(uname)
        w_cbc_file.write(" ")
        w_cbc_file.write(cipher_text)

#Prefix
p = '\xd9_\xa6\xcf\x1dlc\xa0'

#AES-ECB block cipher mode encryption and decryption functions
def ecb_encryption(pword):
    aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_ECB)
    mod = len(pword) % 16
    pad  = 16 - mod
    #Padding
    if pad == 16:
        cipher_text = aes_1.encrypt(pword)
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text
    else:
        pword += '0' * pad
        cipher_text = aes_1.encrypt(pword)
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text

def ecb_decryption(cipher_text):
    c = cipher_text
    cipher_text = base64.b64decode(c)
    aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_ECB)
    plain_text = aes_2.decrypt(cipher_text)
    plain_text = plain_text.strip('0')
    return plain_text

#AES-CTR block cipher mode encryption and decryption functions
def ctr_encryption(pword):
    aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CTR, counter = Counter.new(64, prefix = p))
    cipher_text = base64.b64encode(aes_1.encrypt(pword))
    return cipher_text

def ctr_decryption(cipher_text):
    aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CTR, counter = Counter.new(64, prefix = p))
    plain_text = aes_2.decrypt(base64.b64decode(cipher_text))
    return plain_text

#AES-CBC block cipher mode encryption and decryption functions
def cbc_encryption(pword):
    aes_1 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CBC, 'ThisIsTheIV@666!')
    mod = len(pword) % 16
    pad  = 16 - mod
    #Padding
    if pad == 16:
        cipher_text = aes_1.encrypt(pword)
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text
    else:
        pword += '0' * pad
        cipher_text = aes_1.encrypt(pword)
        cipher_text = base64.b64encode(cipher_text)
        return cipher_text

def cbc_decryption(cipher_text):
    c = cipher_text
    cipher_text = base64.b64decode(c)
    aes_2 = AES.new('Th3K3yI$ally0urb@s3ar3b3l0ngt0u$', AES.MODE_CBC, 'ThisIsTheIV@666!')
    plain_text = aes_2.decrypt(cipher_text)
    plain_text = plain_text.strip('0')
    return plain_text

#Main
def main():
    #Creating files for the database
    open('./ecb_file.txt', 'a')
    open('./ctr_file.txt', 'a')
    open('./cbc_file.txt', 'a')
    #Initializing the variable to count the number of attempts of the master password
    attempt = 0
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    print "\n                      PASSWORD MAN"
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    while(True):
        begin = raw_input("Welcome to Password Man! Do you wish to continue? 1: Yes , 2: No\nYour input: ")
        if begin == '1':
            master_key = raw_input("Enter the master password\n")
            #Master password is hard-coded
            if master_key == 'OneRing':
                command = raw_input("Input your choice:\n 1. Read password\n 2. Write & Save password\n 3. Exit\nYour input: ")
                if command == '1':
                    read_pass()
                elif command == '2':
                    write_pass()
                else:
                    sys.exit(0)
            else:
                print "Wrong master password. Try again. The app will close after 3 wrong attempts!"
                attempt = attempt + 1;
                if attempt == 3:
                    sys.exit(0)
        elif begin == '2':
            sys.exit(0)
        else:
            print "Invalid input!"

if __name__=="__main__":
    main()
