#=======================================================================
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#title           : Personal Hacking Toolkit
#description     :
#author          : fab5
#date            : 1/25/2019 - //2019
#version         : a0.2
#usage           : python menu.py
#notes           :
#devlog:
#
#   25.01.2019: Added Menu
#
#   26.01.2019: Added Dictionary Attack / Wordlist Generator
#
#   28.01.2019: Added Network Tab and completed the Analysis Part
#

#python_version  : 3.6
#=======================================================================


import os, sys, hashlib, string, argparse, itertools, socket
from urllib.request import urlopen
from datetime import datetime


#
# IMPORTING SCRIPTS
#

#
# END IMPORT OF SCRIPTS
#
def wordlist(chrs, min_length, max_length, output):
    if min_length > max_length:
        print("[+] min_length value Should be small or same as max_length")
        sys.exit()

    if os.path.exists(os.path.dirname(output)) == False:
        os.makedirs(os.path.dirname(output))

    print("\n")
    print("[+] creating a wordist at %s " %output)
    start_time = datetime.now()
    print ('[+] Starting at : %s' % start_time)
    output = open(output,'w')

    for n in range(min_length, max_length+1):
        for xs in itertools.product(chrs, repeat=n):
            chars = ''.join(xs)
            output.write("%s\n" % chars)
            sys.stdout.write('\r[+] saving character `%s`' % chars)
            sys.stdout.flush()

    output.close()

    end_time = datetime.now()
    print ('\n[+] Ended at : %s' % end_time )
    print ('\n[+] Total Duration : {}\n'.format(end_time - start_time))

def dictionary_attack(phash, type, dclink):

    if dclink == '':
        dcfile = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
    else:
        dcfile = str(urlopen(dclink).read(), 'utf-8')


    if type == 'md5':
        for guess in dcfile.split('\n'):
            hashedGuess = hashlib.md5(bytes(guess, 'utf-8')).hexdigest()
            if hashedGuess == phash:
                print("The password is ", str(guess))
                os.system('pause')
                menu()
            elif hashedGuess != phash:
                print("Password guess ", str(guess), " does not match, trying next...")

        print("Password couldn't be found. Do you want to try bruteforcing it? (y/n)\n")
        ch = input("Choice: ")

        if ch == y:
            bruteforce(phash, type)
        if ch == n:
            menu()


    elif type == 'sha1':
        for guess in dcfile.split('\n'):
            hashedGuess = hashlib.md5(bytes(guess, 'utf-8')).hexdigest()
            if hashedGuess == phash:
                print("The password is ", str(guess))
                os.system('pause')
                menu()
            elif hashedGuess != phash:
                print("Password guess ", str(guess), " does not match, trying next...")

        print("Password couldn't be found. Do you want to try bruteforcing it? (y/n)\n")
        ch = input("Choice: ")

        if ch == y:
            bruteforce(phash, type)
        if ch == n:
            menu()


    else:
        print("Sorry that type of Hash is currently not supported!")


def detecthashtype(hash):
    #coming soon

def bruteforce(phash, type):


def exit_():
    os.system('cls')
    sys.exit()

def resetchoice():
    choice = 0

def menu():
    resetchoice()
    os.system('cls')
    print(" ######################### ")
    print("  _    _   _______   _  __ ")
    print(" | |  | | |__   __| | |/ / ")
    print(" | |__| |    | |    | ' /  ")
    print(" |  __  |    | |    |  <   ")
    print(" | |  | |    | |    | . \  ")
    print(" |_|  |_|    |_|    |_|\_\ ")
    print(" ~made by fab5 ## ver. a0.2")
    print(" ######################### ")
    print("Welcome,\n")
    print("Please choose:")
    print("1. Social Engeneering")
    print("2. Password Cracking")
    print("3. Scripts")
    print("4. Network")
    print("\n99. Back")

    choice = input(" >>  ")

    if choice == 1: # Social Engeneering

        def submenu1():
            resetchoice()
            os.system('cls')
            print("Social Engeneering\n")
            print("Please choose:")
            print("1. Web Attacking Vectors")
            print("2. ")
            print("3. ")
            print("\n99. Back")

            choice = input(" >>  ")

            if choice == 1:

                def submenu11():
                    resetchoice()
                    os.system('cls')
                    print("Social Engeneering\n")
                    print("\- Web Attackign Vectors\n")
                    print("Please choose:")
                    print("1. Web Attacking Vectors")
                    print("2. ")
                    print("3. ")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice == 1:

                    if choice == 2:

                    if choice == 3:

                    if choice == 99:
                        menu()

                submenu11()

            if choice == 2:

                def submenu12():
                    resetchoice()
                    os.system('cls')
                    print("Social Engeneering\n")
                    print("Please choose:")
                    print("1. Web Attacking Vectors")
                    print("2. ")
                    print("3. ")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice12 == 1:

                    if choice == 2:

                    if choice == 3:

                    if choice == 99:
                        menu()

                submenu12()

            if choice == 3:

                def submenu13():
                    resetchoice()
                    os.system('cls')
                    print("Social Engeneering\n")
                    print("Please choose:")
                    print("1. Web Attacking Vectors")
                    print("2. ")
                    print("3. ")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice == 1:

                    if choice == 2:

                    if choice == 3:

                    if choice == 99:
                        menu()

                submenu13()

            if choice == 99:
                menu()

        submenu1()

    if choice == 2: # Password Cracking

        def submenu2():
            os.system('cls')
            print("Password Cracking\n")
            print("Please choose:")
            print("1. Hash Cracking")
            print("2. Zip-File Cracking")
            print("3. Wordlist Generator")
            print("\n99. Back")

            choice = input(" >>  ")

            if choice == 1: # Hash Cracking
                def submenu21():
                    resetchoice()
                    os.system('cls')
                    print("Password Cracking\n")
                    print("\- Hash Cracking")
                    print("Please choose:")
                    print("1. Dictionary Attack")
                    print("2. Brute-Force")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice == 1:
                        resetchoice()
                        def submenu211():
                            resetchoice()
                            os.system('cls')
                            print("Password Cracking\n")
                            print("\- Hash Cracking")
                            print(" \- Dictionary Attack")
                            print("Please choose the Hash type:")
                            print("1. md5")
                            print("2. sha1")
                            print("\n99. Back")

                            choice = input(" >>  ")

                            if choice == 1:
                                os.system('cls')
                                pha = input("Input Hash Value: ")
                                os.system('cls')
                                durl = input("Input Url to Wordlist (leave blank for default): ")
                                dictionary_attack(pha, 'md5', durl)
                                submenu211()
                            if choice == 2:
                                os.system('cls')
                                pha = input("Input Hash Value: ")
                                os.system('cls')
                                durl = input("Input Url to Wordlist (leave blank for default): ")
                                dictionary_attack(pha, 'sha1', durl)
                                submenu211()
                            if choice == 99:
                                submenu21()

                        submenu211()
                    if choice == 2:
                        resetchoice()
                        def submenu212():
                            resetchoice()
                            os.system('cls')
                            print("Password Cracking\n")
                            print("\- Hash Cracking")
                            print(" \- Bruteforce")
                            print("Please choose:")
                            print("1. md5")
                            print("2. sha1")
                            print("\n99. Back")

                            choice = input(" >>  ")

                            if choice == 1:

                            if choice == 2:

                            if choice == 99:
                                submenu21()

                        submenu212()
                    if choice == 99:
                        submenu2()

                submenu21()
            if choice == 2:
                def submenu22():
                    resetchoice()
                    os.system('cls')
                    print("Password Cracking\n")
                    print("\- Zip-File Cracking")
                    print("Please choose:")
                    print("1. Hash Cracking")
                    print("2. Zip-File Cracking")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice == 1:

                    if choice == 2:

                    if choice == 99:
                        submenu2()

                submenu22()
            if choice == 3:
                resetchoice()
                os.system('cls')
                chrs = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
                os.system('cls')
                min_len = input("Input Minimum Length of Password: ")
                os.system('cls')
                max_len = input("Input Maximum Length of Password: ")
                os.system('cls')
                otput = input("Enter Output Path: ")

                wordlist(chrs, min_len, max_len, otput)
                submenu2()
            if choice == 99:
                menu()

        submenu2()

    if choice == 3: # Scripts

        def submenu3():
            resetchoice()
            os.system('cls')
            print("Scripts\n")
            print("Please choose:")
            print("1. Python")
            print("2. Batch")
            print("3. ")
            print("\n99. Back")

            choice = input(" >>  ")

            if choice == 1:

            if choice == 2:

            if choice == 3:

            if choice == 99:
                menu()

        submenu3()

    if choice == 4: # Network
        def submenu4():
            resetchoice()
            os.system('cls')
            print("Network\n")
            print("Please choose:")
            print("1. Analysis")
            print("2. ")
            print("3. ")
            print("\n99. Back")

            choice = input(" >>  ")

            if choice == 1:
                def submenu41()
                    resetchoice()
                    os.system('cls')
                    print("Network\n")
                    print(" \- Analysis")
                    print("Please choose:")
                    print("1. ARP Scan")
                    print("2. Port Scan")
                    print("3. NMAP Scan")
                    print("\n99. Back")

                    choice = input(" >>  ")

                    if choice == 1:
                        def submenu411()
                            resetchoice()
                            os.system("cls")
                            os.system('arp -a > arpscan.tmp')
                            arp = open("arpscan.tmp", "r")
                            arpscan = arp.read()
                            arp.close()
                            choice = input("Do you want to save the output for later? (y/n) >> ")
                            if choice != 'y':
                                os.system("del /f /s /q arpscan.tmp > nul")
                            if choice == 'y':
                                print("Output saved in running directory as arpscan.tmp!\n")
                            print(arpscan)
                            os.system("pause")
                        submenu411()

                    if choice == 2:
                        def submenu412()
                            resetchoice()
                            os.system('cls')
                            target = input("What IP do you want to check for open ports? >> ")
                            targetIP = socket.gethostbyname(target)
                            tstart = datetime.now()
                            try:
                                for p in range(1, 500):
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    res = sock.connect_ex((targetIP, p))
                                    if res == 0:
                                        print("Port " + str(p) + " is opened.")
                                    else:
                                        print("Port " + str(p) + ' is not opened.')
                                    sock.close()
                            except Exception:
                                print("There was an error.")
                                menu()

                            tend = datetime.now()
                            diff = tend - tstart

                            print("Scan completed in " + str(diff))
                            os.system("pause")
                            submenu41()

                    if choice == 3:
                        def submenu413():
                            resetchoice()
                            os.system("cls")
                            fdip = input("Enter the first number of ips in your net ex.192 (192.168.x.x) >> ")
                            os.system("cls")
                            sdip = input("Enter the second number of ips in your net. ex.168 (192.168.x.x) >> ")
                            os.system("echo nmapscan > nmapscan.tmp")
                            for i in range(1,254):
                                for d in range(1,254):
                                    ip = fdip,".",sdip,".",i,".",d
                                    os.system("cd nmap && nmap.exe -sP ",ip," > ../nmapscan.tmp")

                            nmap = open("nmapscan.tmp", "r")
                            nmapscan = nmap.read()
                            nmap.close()
                            choice = input("Do you want to save the output for later? (y/n) >> ")
                            if choice != 'y':
                                os.system("del /f /s /q nmapscan.tmp > nul")
                            if choice == 'y':
                                print("Output saved in running directory as nmapscan.tmp!\n")
                            print(arpscan)
                            os.system("pause")

                        submenu413()
                submenu41()

        submenu4()
    if choice == 99:
        exit_()
menu()
