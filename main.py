import os
from datetime import time
from random import random
from tkinter import *
from tkinter.filedialog import askopenfile
import hashlib
from pathlib import Path
import time
import math
import random
from tkinter import messagebox
import re

# <editor-fold desc="Root gui">
...


def donothing():
    filewin = Toplevel(root)
    button = Button(filewin, text="Do nothing button")
    button.pack()


root = Tk()
menubar = Menu(root)
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="New", command=donothing)
filemenu.add_command(label="Open", command=donothing)
filemenu.add_command(label="Save", command=donothing)
filemenu.add_command(label="Save as...", command=donothing)
filemenu.add_command(label="Close", command=donothing)

filemenu.add_separator()

filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="Help Index", command=donothing)
helpmenu.add_command(label="About...", command=donothing)
menubar.add_cascade(label="Help", menu=helpmenu)

root.config(menu=menubar)
# </editor-fold
# <editor-fold desc="Functions">
...


def open_file():
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        f.read()
        filedetails(path)
        setTextInput(path, '1')

def open_keyfile():
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        filecontent = f.read()
        text = filecontent
        setTextInput(text, '5')

def open_nfile():
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        filecontent = f.read()
        text = filecontent
        setTextInput(text, '6')

def open_fileReciever():
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        f.read()
        setTextInput(path, '3')


def filedetails(filepath):
    split_tup = os.path.splitext(filepath)
    print(split_tup)
    file_extension = split_tup[1]
    filename = Path(filepath).stem
    filezie = Path(filepath).stat().st_size
    modified = os.path.getmtime(filepath)
    datemodify = ("Date modified: " + time.ctime(modified))
    created = os.path.getctime(filepath)
    creationdate = ("Date created: " + time.ctime(created))
    left1.config(text="Name: " + filename)
    left2.config(text="Type: " + file_extension)
    left3.config(text="Location: " + filepath)
    left4.config(text="size: " + filezie.__str__() + " byte")
    left5.config(text=creationdate)
    left6.config(text=datemodify)


def Hash(string):
    hash_sha3_512 = hashlib.new("sha3_512", string.encode())
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\result.txt', 'w')
    s = hash_sha3_512.hexdigest()
    ff.writelines(s)
    ff.close()
    return s

def decrypt():
    path = rE.get()
    f = open(path, 'r')
    filecontent = f.read()
    ints=re.findall(r'\d+', filecontent)
    for i in range(0, len(ints)):
        ints[i] = int(ints[i])
    ciphertext =ints
    key = int(pubkey.get())
    n = int(pubn.get())
    aux = [str(pow(char, key, n)) for char in ciphertext]
    plain = [chr(int(char2)) for char2 in aux]
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\Results_Reviver\\DecryptedResult.txt','w')
    reult=''.join(plain)
    ff.writelines(reult)
    ff.close()
    #resultDecrypted.config(text="Decrypted result: "+''.join(plain))

def Hashreceiver():
    path = rE.get()
    f = open(path, 'r')
    filecontent = f.read()
    text = filecontent
    hash_sha3_512 = hashlib.new("sha3_512", text.encode())
    s = hash_sha3_512.hexdigest()
    directory = "Results_Reviver"
    parent_dir = "C:/Users/yadog/Desktop/RSA"

    try:
        path = os.path.join(parent_dir, directory)
        os.mkdir(path)
    except FileExistsError:
        print("Directory ", directory, " already exists")
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\%s\\hashedReciever.txt'%directory, 'w')
    ff.writelines(s)
    ff.close()
    #resulthash.config(text="Hash: "+s.__str__())

    return s



def SavePublic():
    name = 'public'
    ex = 'txt'
    content =pubkeyE.get()+","+pubNE.get()
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\' + name + '.' + ex, 'w')
    ff.writelines(content)
    ff.close()


def SavePrivate():
    name = 'private'
    ex = 'txt'
    content = E3.get()
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\' + name + '.' + ex, 'w')
    ff.writelines(content)
    ff.close()


def LoadKey():
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        filecontent = f.read()
        setTextInput(filecontent, '1')
    file = askopenfile(mode='r', filetypes=[('All Files', '*.*')])
    if file is not None:
        path = file.name
        f = open(path, 'r')
        filecontent = f.read()
        setTextInput(filecontent, '2')


def setTextInput(text, entry):
    if entry == '1':
        E1.delete(0, "end")
        E1.insert(0, text)
    elif entry == '2':
        E3.delete(0, "end")
        E3.insert(0, text)
    elif entry == '4':
        E4.delete(0, "end")
        E4.insert(0, text)
    elif entry == '3':
        rE.delete(0, "end")
        rE.insert(0, text)
    elif entry == '5':
        pubkey.delete(0, "end")
        pubkey.insert(0, text)
    elif entry == '6':
        pubn.delete(0, "end")
        pubn.insert(0, text)
    elif entry == '8':
        pubkeyE.delete(0, "end")
        pubkeyE.insert(0, text)
    elif entry == '9':
        pubNE.delete(0, "end")
        pubNE.insert(0, text)
    else:
        E1.delete(0, "end")
        E1.insert(0, text)


def is_prime(num):
    if (num <= 3 or num % 2 == 0):
        return num != 2 and num != 3
    divisor = 3
    while ((divisor <= math.sqrt(num)) and (num % divisor != 0)):
        divisor += 2
    return num % divisor == 0


def keys():
    num = random.randint(100000000000000, 900000000000000)
    while is_prime(num):
        num = random.randint(100000000000000, 900000000000000)
    return num


def generateE(phi):
    num = random.randint(1000000000000, 9000000000000)
    while is_prime(num) and not num % phi == 0:
        num = random.randint(10000000000, 90000000000)
    return num


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    if temp_phi == 1:
        return d + phi


def generate_key_pair():
    p = keys()
    q = keys()
    while is_prime(q):
        q = random.randint(10000, 90000)
    if (is_prime(p) and is_prime(q)):
        raise ValueError('Please ENTER two Prime Numbers')
    elif p == q:
        raise ValueError('p and q can"t be the SAME')
    n = p * q
    phi = (p - 1) * (q - 1)
    ee = generateE(phi)
    if (ee < phi and ee > 1):
        e = ee
    else:
        messagebox.showerror("Error", "Th number you entered is not compitable MUST be Between 1 and Phi")
    e = ee
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)

    return ((e, n), (d, n))


def keysGenerate():
    keys = generate_key_pair()
    public, private = keys
    pk = private
    prikey, prin = pk

    puk=public
    pubkey,pubn=puk

    file = open('C:\\Users\\yadog\\Desktop\RSA\\PrivateKey.txt', 'w')
    file.writelines(prikey.__str__())
    file.close()
    file = open('C:\\Users\\yadog\\Desktop\RSA\\Prin.txt', 'w')
    file.writelines(prin.__str__())
    file.close()
    setTextInput(prikey.__str__(), "2")
    setTextInput(prin.__str__(), "4")

    file = open('C:\\Users\\yadog\\Desktop\RSA\\Pubkey.txt', 'w')
    file.writelines(pubkey.__str__())
    file.close()

    file = open('C:\\Users\\yadog\\Desktop\RSA\\Pubn.txt', 'w')
    file.writelines(pubn.__str__())
    file.close()
    setTextInput(pubkey.__str__(), "8")
    setTextInput(pubn.__str__(), "9")




def createsign():
    path = E1.get()
    f = open(path, 'r')
    filecontent = f.read()
    text = filecontent
    key = int(E3.get())
    n = int(E4.get())

    s = Hash(text)
    cipher = [pow(ord(char), key, n) for char in s]
    ff = open('C:\\Users\\yadog\\Desktop\RSA\\hashed.txt', 'w')
    ff.writelines(cipher.__str__())
    ff.close()


# </editor-fold
# <editor-fold desc="labelframe">
...
labelframe = LabelFrame(root, text="Select a file to sign:", padx=8)

B1 = Button(labelframe, text="Browse", command=open_file, width=15)
B1.grid(row=0, column=1)

E1 = Entry(labelframe, width=55)
E1.grid(row=0, column=0)

labelframe.grid(row=0, column=0,sticky=W)

# </editor-fold
# <editor-fold desc="labelframe1">
...
labelframe1 = LabelFrame(root, text="File Details", padx=103, pady=5)

left1 = Label(labelframe1, text="Name:")
left1.grid(row=0, column=0)
left2 = Label(labelframe1, text="Type of file:")
left2.grid(row=1, column=0)
left3 = Label(labelframe1, text="Location:")
left3.grid(row=2, column=0)
left4 = Label(labelframe1, text="Size:")
left4.grid(row=3, column=0)
left5 = Label(labelframe1, text="Created:")
left5.grid(row=4, column=0)
left6 = Label(labelframe1, text="Modified:")
left6.grid(row=5, column=0)

labelframe1.grid(row=1, column=0, pady=10,sticky=W)
# </editor-fold
# <editor-fold desc="labelframe2">
...
labelframe2 = LabelFrame(root, text="Key pair", padx=70, pady=5)

left7 = Label(labelframe2, text="Generate a public/private keypair:")
left7.grid(row=0, column=1, sticky=W)

L2 = Label(labelframe2, text="Public Key")
L2.grid(row=1, column=1, sticky=W)

pubkeyE = Entry(labelframe2, bd=5, width=10)
pubkeyE.grid(row=2, column=1)
pubNE = Entry(labelframe2, bd=5, width=10)
pubNE.grid(row=3, column=1)

L3 = Label(labelframe2, text="Private Key")
L3.grid(row=1, column=2, sticky=W)

E3 = Entry(labelframe2, bd=5, width=10)
E3.grid(row=2, column=2)

E4 = Entry(labelframe2, bd=5, width=10)
E4.grid(row=3, column=2, ipadx=1, ipady=2)

B3 = Button(labelframe2, text="Save", command=SavePublic, width=15)
B3.grid(row=5, column=1, sticky=W)

B4 = Button(labelframe2, text="Load", command=LoadKey)
B4.grid(row=5, column=1, sticky=W)

B5 = Button(labelframe2, text="Save", command=SavePrivate, width=15)
B5.grid(row=5, column=2, sticky=W)

B6 = Button(labelframe2, text="Load", command=LoadKey)
B6.grid(row=5, column=2, sticky=W)

B2 = Button(labelframe2, text="Generate", command=keysGenerate, width=20)
B2.grid(row=0, column=2, sticky=W)

labelframe2.grid(row=2, column=0, sticky=W)
# </editor-fold
# <editor-fold desc="labelframe3">
...
labelframe3 = LabelFrame(root, text="Receiver", padx=70, pady=5)

r1 = Label(labelframe3, text="Path")
r1.grid(row=1, column=0, sticky=W)

rE = Entry(labelframe3, bd=5, width=10)
rE.grid(row=1, column=1, ipadx=100, ipady=5)

rB = Button(labelframe3, text="Browse", command=open_fileReciever, width=15)
rB.grid(row=1, column=2, sticky=W, pady=10)

rD = Button(labelframe3, text="Decrypt", command=decrypt, width=15)
rD.grid(row=6, column=2, sticky=W, pady=10)

rH = Button(labelframe3, text="Hash", command=Hashreceiver, width=15)
rH.grid(row=7, column=2, sticky=W, pady=10)

resulthash = Label(labelframe3, text="Hashed result:")
resulthash.grid(row=3, column=0, sticky=W,columnspan=3)

resultDecrypted = Label(labelframe3, text="Decrypted result:")
resultDecrypted.grid(row=4, column=0, sticky=W)

publiclbl = Label(labelframe3, text="public keys:")
publiclbl.grid(row=5, column=0, sticky=W)

keylbl = Label(labelframe3, text="key:")
keylbl.grid(row=6, column=0, sticky=W)

pubkey = Entry(labelframe3, bd=5, width=10)
pubkey.grid(row=6, column=1, ipadx=50, ipady=5)

nlbl = Label(labelframe3, text="N value:")
nlbl.grid(row=7, column=0, sticky=W)

pubn = Entry(labelframe3, bd=5, width=10)
pubn.grid(row=7, column=1, ipadx=50, ipady=5)

rkeybtn = Button(labelframe3, text="load key value", command=open_keyfile, width=15)
rkeybtn.grid(row=8, column=1)

rnbtn = Button(labelframe3, text="load n value", command=open_nfile, width=15)
rnbtn.grid(row=9, column=1)

labelframe3.grid(row=1, column=1, sticky=W)
# </editor-fold
B7 = Button(root, text="Create Signature", command=createsign)
B7.grid(row=6, column=0, sticky=W)
root.mainloop()
