import binascii
import sys
from datetime import datetime, date, timedelta
import time
import matplotlib.pyplot as plt
from flask import Flask,render_template,request
import mcrpc
import subprocess
from Crypto.Cipher import AES
import os
import pyrebase

# config = {
#     'apiKey': "AIzaSyCOjJy7knbfdS5S5mVrM5XI0A-smuAWD1s",
#     'authDomain': "test-ac807.firebaseapp.com",
#     'databaseURL': "https://test-ac807.firebaseio.com",
#     'projectId': "test-ac807",
#     'storageBucket': "test-ac807.appspot.com",
#     'messagingSenderId': "45638555993",
#     'appId': "1:45638555993:web:bf01701c47d4881e721448",
#     'measurementId': "G-BCVXJTSVYV"
# }
# chainname = "final"
# firebase = pyrebase.initialize_app(config)
# storage = firebase.storage()
# file_path = os.environ['HOME'] + "/Desktop/hello.txt"
# auth = firebase.auth()
# storage.child("multichain/final/data/syslog.txt").put("/var/log/syslog")


print(os.getcwd())
# storage.child("multichain/final/data/syslog.txt").download("check.txt")


def convert_to_list(string):
    li = list(string.split(" "))
    return li


def get_cipher():

    password_ = "openssl rand -base64 48"
    out = subprocess.Popen(convert_to_list(password_),
               stdout=subprocess.PIPE,
               stderr=subprocess.STDOUT)
    password,stderr = out.communicate()
    password = password.decode().replace("\n", "")
    # print(password.decode())
    address = "/var/log/syslog"

    cipherhex_cmd = "openssl enc -aes-256-cbc -in " + address + " -pass pass:" + password +" | xxd -p -c 99999 > out.txt"
    os.system(cipherhex_cmd)
    with open("out.txt", 'rb') as f:
        cipherhex = f.read()
    #
    # out = subprocess.Popen(convert_to_list(cipherhex_cmd),
    #            stdout=subprocess.PIPE,
    #            stderr=subprocess.STDOUT)
    # cipherhex,stderr = out.communicate()
    cipherhex = cipherhex.decode()
    print("Cipherhex: ", cipherhex)
    print(type(cipherhex))
    return password, cipherhex


def get_password():
    password_cmd = "openssl rand -base64 48"
    out = subprocess.Popen(convert_to_list(password_cmd), # run openssl command using subprocess
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    password, stderr = out.communicate()
    password = password.decode().replace("\n", "") # strip the extra newline
    return password  # get a random aes password

def get_cipher_hex(filepath, password):
    password = get_password()
    filepath = "/var/log/syslog"
    cipherhex_cmd = "openssl enc -aes-256-cbc -in " + filepath + " -pass pass:" + password +" | xxd -p -c 99999 > out.txt"
    os.system(cipherhex_cmd)
    with open("out.txt", 'rb') as f:
        cipherhex = f.read()
    return cipherhex # get the encoded file in publishable hex format


def save_hex_to_local(txid, cipherhex):
    txid = "test"
    cipherhex = get_cipher_hex()
    data = cipherhex.decode()
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/stream-data/'
    if not os.path.exists(file_path):
        os.system("mkdir " + file_path)
    with open(file_path + txid + ".txt", "wb") as file:
        file.write(data)  # save the uploaded file to local directory



def get_hex():
    data = ""
    file_path = "/var/log/syslog"
    with open(file_path, 'rb') as file:
        data = file.read()
    return binascii.hexlify(data)  # get the hex representation of the file

# returns the chain configuration for rpc in a dictionary
def get_rpc_config(file_name):
    with open(file_name, 'r') as file:
        data = file.read()
    rpc = {}
    data = data.split("\n")
    for item in data:
        token = item.split('=')
        rpc[token[0]] = token[1]
    return rpc


rpc_config = get_rpc_config('config.txt')
rpcuser = rpc_config['rpc-user']
rpchost = rpc_config['rpc-host']
rpcport = rpc_config['rpc-port']
rpcpasswd = rpc_config['rpc-password']
chainname = rpc_config['chain-name']
homedir = os.environ['HOME']


client = c = mcrpc.RpcClient(rpchost,rpcport,rpcuser,rpcpasswd)

# li = ['hello','world']
# st = str(li)
# st = st.replace("[", "")
# st = st.replace("]", "")
# print(st)
# print(str(li))

import schedule


def foo():
    print('hello')


# schedule.every(0.1).seconds.do(foo)
# while True:
#     schedule.run_pending()
#     time.sleep(1)

def publish_stream(cc):
    while True:
        data = ""
        file_path = "/var/log/syslog"
        with open(file_path, 'rb') as file:
            data = file.read()
        hex_string = binascii.hexlify(data)
        # hex_string = data.hex()
        # hex_string = hex_string.hex()
        # print(hex_string)
        # print(type(hex_string))
        txid = cc.publishfrom("16nwUYqr4SgcvofHEejDpeW26syhssrXry8YaN", "test", "keygiven2", hex_string)
        print("txid: ", txid)
        file_path = os.environ['HOME']+ '/.multichain/' + "final" + '/stream-data/'
        with open(file_path + txid + ".txt", "wb" ) as file:
            file.write(data)
        print("sleeping for 1330 seconds")
        time.sleep(1330 )

# rpcuser = 'multichainrpc'
# rpcpasswd = '38k73hAxWaSE16w6g1z5RAYbna9g7hBQx4HPGqDVxErD'
# rpchost = 'localhost'
# rpcport = '4776'
# chainname = 'final'
# client = c = mcrpc.RpcClient(rpchost,rpcport,rpcuser,rpcpasswd)
#
# publish_stream(c)
#
# def confidential_publish(from_address):
#     haspermission = c.listpermissions('send', from_address)
#     password, cipherhex = test.get_cipher()
#     if haspermission:
#         cipherhex = cipherhex.encode().hex()
#         txid = c.publishfrom(from_address, 'items', 'syslog', cipherhex)  # publish the log data
#         print(txid)
#         mkdir_ = "mkdir ~/.multichain/" + chainname + "/stream-passwords/"
#         multi_dir = homedir + '/.multichain/' + chainname + '/stream-passwords/'
#         if not os.path.exists(multi_dir):
#             os.system(mkdir_)
#         multi_dir = homedir + '/.multichain/' + chainname + '/stream-data/'
#         mkdir_ = "mkdir ~/.multichain/" + chainname + "/stream-data/"
#         if not os.path.exists(multi_dir):
#             os.system(mkdir_)
#         print("Password ", password)
#         print("Cipherhex", str(cipherhex))
#         print("Txid", txid)
#         # save_pwd = "echo "+ password +" > ~/.multichain/"+chainname+"/stream-passwords/"+txid+".txt"
#         # print("save pwd: ", save_pwd)
#         multi_dir = homedir + '/.multichain/' + chainname + '/stream-passwords/'
#         os.chdir(multi_dir)
#         print(os.getcwd())
#         with open(str(txid) + ".txt", 'w+') as f:
#             f.write(password)
#             f.close()
#         # save_cipherhex = "echo "+ cipherhex +" > ~/.multichain/"+chainname+"/stream-data/"+txid+".txt"
#         # print("save cipherhex", save_cipherhex)
#         multi_dir = homedir + '/.multichain/' + chainname + '/stream-data/'
#         with open(str(txid) + ".txt", 'w+') as f:
#             f.write(cipherhex)
#             f.close()
#         c.subscribe("pubkeys")
#         txid2 = c.liststreampublisheritems("pubkeys", "1FhFCi1pqKo9Xj22hS3hteQA2XSdcR8cnTFMuD", True, 1)
#         txid2 = txid2[0]['txid']
#         print("Txid2 ", txid2)
#         pubkey_ = "multichain-cli " + chainname + " gettxoutdata " + txid2 + " # | tail -n 1 | xxd -p -r > /tmp/pubkey.pem"
#         os.system(pubkey_)
#         keycipher_ = "echo " + password + " | openssl rsautl -encrypt -inkey /tmp/pubkey.pem -pubin | xxd -p -c 9999 > out.txt"
#         with open("out.txt", 'rb') as f:
#             keycipherhex = f.read()
#             f.close()
#         label = txid + "-" + to_address
#         c.publishfrom(from_address, "access", label, bin2hex(keycipherhex))
#         print("Ok done....")
#         return "File published"
#     else:
#         return "This address: " + from_address + " doesn't have permission to publish"


def tiem():
    now = datetime.now()
    print("now =", now)
    print(type(now))
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    print("date and time =", dt_string)
    print(type(dt_string))


def get_hex():
    data = ""
    file_path = "/var/log/syslog"
    with open(file_path, 'rb') as file:
        data = file.read()
    return binascii.hexlify(data)


def retrieve_hex_from_multichain(txid):
    try:
        multi_data = c.gettxoutdata(txid, 0)
        return multi_data  # retrieve hex data from multichain
    except:
        return "Wrong_txid"


def publish_con():
    global homedir
    if request.method == "POST":
        from_address = request.form['fromaddress']
        to_address = request.form['toaddress']
        item_stream = request.form['stream']
        to_address = "16nwUYqr4SgcvofHEejDpeW26syhssrXry8YaN"
    haspermission = c.listpermissions('send', from_address)
    password, cipherhex = test.get_cipher()
    if haspermission:
        cipherhex = cipherhex.encode().hex()
        txid = c.publishfrom(from_address, 'items', 'syslog', cipherhex)  # publish the log data
        print(txid)
        mkdir_ = "mkdir ~/.multichain/" + chainname + "/stream-passwords/"
        multi_dir = homedir + '/.multichain/' + chainname + '/stream-passwords/'
        if not os.path.exists(multi_dir):
            os.system(mkdir_)
        multi_dir = homedir + '/.multichain/' + chainname + '/stream-data/'
        mkdir_ = "mkdir ~/.multichain/" + chainname + "/stream-data/"
        if not os.path.exists(multi_dir):
            os.system(mkdir_)
        print("Password ", password)
        print("Txid", txid)
        # save_pwd = "echo "+ password +" > ~/.multichain/"+chainname+"/stream-passwords/"+txid+".txt"
        # print("save pwd: ", save_pwd)
        multi_dir = homedir + '/.multichain/' + chainname + '/stream-passwords/'
        os.chdir(multi_dir)
        print(os.getcwd())
        with open(str(txid) + ".txt", 'w+') as f:
            f.write(password)
        # save_cipherhex = "echo "+ cipherhex +" > ~/.multichain/"+chainname+"/stream-data/"+txid+".txt"
        # print("save cipherhex", save_cipherhex)
        multi_dir = homedir + '/.multichain/' + chainname + '/stream-data/'
        with open(str(txid) + ".txt", 'w+') as f:
            f.write(cipherhex)
        c.subscribe("pubkeys")
        txid2 = c.liststreampublisheritems("pubkeys", to_address, True, 1)
        txid2 = txid2[0]['txid']
        print("Txid2 ", txid2)
        vout = 0
        pubkey_ = "multichain-cli " + chainname + " gettxoutdata " + txid2 + " " + str(vout) +  " | tail -n 1 | xxd -p -r > /tmp/pubkey.pem"
        print(pubkey_)
        os.system(pubkey_)
        keycipher_ = "echo " + password + " | openssl rsautl -encrypt -inkey /tmp/pubkey.pem -pubin | xxd -p -c 9999 > /tmp/out1.txt"
        print(keycipher_)
        os.system(keycipher_)
        with open("/tmp/out1.txt", 'rb') as f:
            data = f.read()
            f.close()
        label = txid + "-" + to_address
        data = binascii.hexlify(data)
        # print("data",data)
        c.publishfrom(from_address, "access", label, data)
        print("Ok done....")

        return "File published at txid " + txid
    else:
        return "This address: " + from_address + " doesn't have permission to publish"


def retrieve_confidential(txid="b031b75efd8849f1f8d62b71b105ec03dbfd72d77f249700fb54379be56be142"):
    c.subscribe("items")
    c.subscribe("access")
    label = txid + "-" + "16nwUYqr4SgcvofHEejDpeW26syhssrXry8YaN"
    print(label)
    # access_cmd = "multichain-cli " + chainname + " liststreamkeyitems " + "access " + label + " true"
    # out = subprocess.Popen(conver_to_list(access_cmd),
    # stdout=subprocess.PIPE,
                    # stderr=subprocess.STDOUT)
    # output, stderr = out.communicate()
    # output = output.decode().replace("\n", "")
    output = c.liststreamkeyitems("access", label, True)
    print(output)
    txid3_pass = output[0]['txid']
    print(txid3_pass)
    key_cipher_hex = c.gettxoutdata(txid3_pass, 0)
    print("keycipher", key_cipher_hex)
    password_cmd = "echo " + key_cipher_hex + " | xxd -p -r | openssl rsautl -decrypt -inkey ~/.multichain/" + chainname + "/stream-privkeys/" + \
                    "16nwUYqr4SgcvofHEejDpeW26syhssrXry8YaN" + ".pem"
    # out = subprocess.Popen(conver_to_list(password_cmd),
    # stdout=subprocess.PIPE,
    # stderr=subprocess.STDOUT)
    # output, stderr = out.communicate()mu
    os.system(password_cmd)

    # lis = json.loads(output)
    # print(type(lis), lis)
    # os.system(access_cmd)


def read_file(dt, start, end):
    # dt = "Oct 06 00:00:00"
    # isascii = lambda s: len(s) == len(s.encode())
    time_mask = "%b %d %H:%M:%S"
    # tm = "Jul 23 09:25:31"
    # tmp = datetime.strptime(tm,time_mask)
    # print(tmp)
    os.chdir(os.environ['HOME'])
    f_name = "/var/log/syslog"
    with open(f_name, "r") as f:
        data = f.read()

    lines = data.split("\n")
    start_date = datetime.strptime(dt + " " + start, time_mask)
    end_date = datetime.strptime(dt + " " + end, time_mask)

    # print(start_date)
    # print(end_date)

    data = ""
    for line in lines:
        words = line.split(" ")
        # print(len(words))
        # print(words)
        if len(words) > 1:
            if words[1] == '':
                words[1] = '0'
                dt1 = words[0] + " " + words[1] + words[2] + " " +  words[3]
            else:
                dt1 = words[0] + " " +  words[1] + " " + words[2]
            # print(dt1)
            date_obj = datetime.strptime(dt1, time_mask)
            if date_obj >= start_date and date_obj < end_date:
                # print(line)
                data += line + "\n"
            if date_obj > end_date:
                break

    print(data)
    return data


# # read_file("Oct 12", "00:00:00", "23:59:59")
# today = date.today()
# time_mask = "%m/%d/%y"
# d2 = today.strftime("%m/%d/%y")
# start_date = datetime.strptime(d2, time_mask)
# print(start_date.strftime("%Y-%m-%d"))
# # d2 = d2.strftime("%y-%m-%d")
# print("d2 =", d2)
#
# t = time.localtime()
# current_time = time.strftime("%H:%M:%S", t)
# print(current_time)
#
# d = datetime.today() - timedelta(hours=3)
#
# dt = d.strftime('%H:%M:%S')
# print(dt)

# def daterange(start_date, end_date):
#     for n in range(int ((end_date - start_date).days)):
#         yield start_date + timedelta(n)
#
# start_date = date(2019, 1, 1)
# end_date = date(2019, 1, 2)
# print(start_date)
# for single_date in daterange(start_date, end_date):
#     print(single_date.strftime("%Y-%m-%d"))

#
# start_date = date(2019, 1, 1)
# end_date = date(2019, 1, 5)
# delta = timedelta(days=1)
# while start_date <= end_date:
#     print (start_date.strftime("%Y-%m-%d"))
#     start_date += delta


def find_chunk_size(dt, start):
    time_mask = "%b %d %H:%M:%S"
    os.chdir(os.environ['HOME'])
    # f_name = "test.txt"
    f_name = "/var/log/syslog"
    with open(f_name, "r") as f:
        data = f.read()
    lines = data.split("\n")
    length = len(lines)
    start_time = datetime.strptime(dt + " " + start, time_mask)

    delta = timedelta(hours=3)
    end_time = start_time + delta
    line = lines[0]
    li = []
    cnt = 0
    while True:
        for i in range(length):
            words = line.split(" ")
            if len(words) > 1:
                if words[1] == '':
                    words[1] = '0'
                    dt1 = words[0] + " " + words[1] + words[2] + " " + words[3]
                else:
                    dt1 = words[0] + " " + words[1] + " " + words[2]
                try:
                    date_obj = datetime.strptime(dt1, time_mask)
                except:
                    print("printing here: error occurred", date_obj)
                    pass
                if date_obj >= start_time and date_obj < end_time:
                    # print(line)
                    data += line + "\n"
                    line = lines[i+1]
                if date_obj > end_time:
                    print(start_time.strftime("%b %d %H:%M:%S"),"---->\t", end_time.strftime("%b %d %H:%M:%S"), sys.getsizeof(data),len(data) ,end=" ")
                    print("\n")
                    li.append((sys.getsizeof(data), len(data)))
                    data = ""
                    start_time = end_time
                    end_time = start_time + delta
                    continue
        break

    print(len(li))
    sum_len = 0
    sum_byte = 0
    sum_0 = len(li)
    non_zero_cnt = 0
    for x in li:
        if x[1] != 0:
            sum_byte += x[0]
            sum_len += x[1]
            sum_0 -= 1
            non_zero_cnt += 1
    print("bytes == ", sum_byte, "len == ", sum_len)
    print("avg_bytes == ", sum_byte/non_zero_cnt, "zero length time interval == ", len(li)-non_zero_cnt)

    # print(data)
    # print(data.__sizeof__())
    # return data


# find_chunk_size("Oct 14", "00:00:00")
def get_current_date_string():
    today = date.today()
    # dd/mm/YY
    dt = today.strftime("%d/%m/%Y")
    # print("date =", dt)
    return dt


def save_to_local_dir(txid,hex_string):
    data = binascii.unhexlify(hex_string)
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/overhead-data/'
    if not os.path.exists(file_path):
        os.system("mkdir " + file_path)
    with open(file_path + txid + ".txt", "wb") as file:
        file.write(data)


def get_hex(size,i):
    with open("Datasets/" + str(size) + "K/" + str(i) + ".txt","rb") as file:
        print("Datasets/" + str(size) + "K/" + str(i) + ".txt")
        data = file.read()
    return binascii.hexlify(data)


from_address = "16nwUYqr4SgcvofHEejDpeW26syhssrXry8YaN"
to_stream = "items"


def compute_publish_overhead(filesizes, no_of_file):
    time_list = []
    for size in filesizes:
        sum_of_time = 0
        for i in range(1,no_of_file + 1):
            hex_data = get_hex(size,i)
            key = get_current_date_string() + "-overhead" + str(size)
            start_time = time.time()
            txid = c.publishfrom(from_address, to_stream, key, hex_data)
            time_taken = time.time() - start_time
            print(time_taken)
            sum_of_time += time_taken
            save_to_local_dir(txid, hex_data)

        avg_time = sum_of_time / no_of_file
        time_list.append(avg_time)
    print(time_list)
    return time_list


def compute_retrieve_overhead(filesizes, no_of_file):
    time_list = []
    for size in filesizes:
        sum_of_time = 0
        tx_count = 0
        key = get_current_date_string() + "-overhead" + str(size)
        list_tx_by_key = c.liststreamkeyitems(to_stream, key)
        for tx in list_tx_by_key:
            txid = tx['txid']
            start_time = time.time()
            multi_data = c.gettxoutdata(txid, 0)
            time_taken = time.time() - start_time
            sum_of_time += time_taken
            tx_count += 1
        avg_time = sum_of_time / tx_count
        time_list.append(avg_time)
    return time_list

filesizes = [250, 500, 750, 1000,1500, 2000]
# filesizes = [1, 2, 3, 4, 5, 6, 7, 8]
# times_pub = compute_publish_overhead(filesizes,10)
# times_ret = compute_retrieve_overhead(filesizes,10)
# plt.plot(filesizes, times_pub)
# plt.plot(filesizes, times_ret)

# plt.title("Publish vs Retrieval Overhead")
# plt.xlabel("File Size (KB)")
# plt.ylabel("Time")
# plt.legend(["Publish","Retrieval"])
# plt.show()

def hex_to_string(hex_data):
    byte_data = binascii.unhexlify(hex_data)
    str_data = byte_data.decode()
    return str_data # converts hex data to string data


def get_items_by_stream(stream_name):
    item_list = c.liststreamitems(stream_name)
    li = []
    dic = {}
    for item in item_list:
        dic['txid'] = item['txid']
        dic['publisher'] = item['publishers'][0]
        dic['key'] = item['keys'][0]
        hex_data = c.gettxoutdata(item['txid'], 0, 100) # returns first 100 byte of data
        data = hex_to_string(hex_data)
        dic['data'] = data
        li.append(dic)
    print(li)
    return li


get_items_by_stream("test")


