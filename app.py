import binascii
import codecs
import threading
import time
from flask import Flask,render_template,request
from datetime import datetime, date, timedelta
import mcrpc
import subprocess
from Crypto.Cipher import AES
import os
from Crypto.PublicKey import RSA
import pyrebase

app = Flask(__name__)


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
# chain configuration


fire_base_config = {
    'apiKey': "AIzaSyCOjJy7knbfdS5S5mVrM5XI0A-smuAWD1s",
    'authDomain': "test-ac807.firebaseapp.com",
    'databaseURL': "https://test-ac807.firebaseio.com",
    'projectId': "test-ac807",
    'storageBucket': "test-ac807.appspot.com",
    'messagingSenderId': "45638555993",
    'appId': "1:45638555993:web:bf01701c47d4881e721448",
    'measurementId': "G-BCVXJTSVYV"
}  # configuration of firebase database
firebase = pyrebase.initialize_app(fire_base_config) # connect firebase
storage = firebase.storage() # init the database


client = c = mcrpc.RpcClient(rpchost,rpcport,rpcuser,rpcpasswd)
addresses = c.getaddresses()
# streams = c.liststreams()
# list_streams = c.liststreams('*',True)
# peers = c.getpeerinfo()
# node_info = c.getinfo()
# json rpc commands


def bin2hex(binStr):
    return binascii.hexlify(binStr)
# convert binary to hex format


def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)
# convert hex to binary


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


def get_hex(dt, start, end):
    data = read_file(dt,start,end)
    data = data.encode()
    return binascii.hexlify(data)  # get the hex representation of the file chunk


def save_to_local_dir(txid,hex_string):
    data = binascii.unhexlify(hex_string)
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/stream-data/'
    if not os.path.exists(file_path):
        os.system("mkdir " + file_path)
    with open(file_path + txid + ".txt", "wb") as file:
        file.write(data)  # save the uploaded file to local directory


def save_to_firebase(txid, hex_string):
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/stream-data/' + txid + '.txt'
    storage.child("multichain/" + chainname + "/data/" + txid + ".txt").put(file_path)


def retrieve_hex_from_multichain(txid):
    try:
        multi_data = c.gettxoutdata(txid, 0)
        return multi_data  # retrieve hex data from multichain
    except:
        return "Wrong_txid"


def retrieve_hex_from_local(txid, file_path = homedir + '/.multichain/' + chainname + '/stream-data/'):

    data = ""
    try:
        with open(file_path + txid + ".txt", "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("Wrong file or file path")
        return "File_Removed"
    return data.hex()   # retrieve hex data from local directory


def retrieve_hex_from_firebase(txid):
    storage.child("multichain/" + chainname + "/data/" + txid + ".txt").download("firebase.txt")
    with open("firebase.txt","rb") as f:
        data = f.read()
    return data.hex()


def match_file(txid):
    multi_data = retrieve_hex_from_multichain(txid) # get the multichain hex data
    hex_data = retrieve_hex_from_local(txid)  # get the local hex data
    return multi_data == hex_data  # match the multichain file with local file


def rebuild_multichain_file(txid):
    multi_data = retrieve_hex_from_multichain(txid)  # get the multichain hex data
    str_data = hex_to_string(multi_data)  # convert the multidata to string
    return str_data  # rebuild multichain file to readable string


def get_current_datetime_string():
    now = datetime.now()
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    print("date and time =", dt_string)
    return dt_string   # get the current date and time in string format


def get_current_date_string():
    today = date.today()
    # dd/mm/YY
    dt = today.strftime("%d/%m/%Y")
    # print("date =", dt)
    return dt  # get the current date in string format


def hex_to_string(hex_data):
    byte_data = binascii.unhexlify(hex_data)
    str_data = byte_data.decode()
    return str_data # converts hex data to string data


def publish_periodically(from_addr, str_name = "test"):
    current_time = datetime.today()
    start_time = current_time - timedelta(hours=3)
    start = start_time.strftime('%H:%M:%S')
    end = current_time.strftime('%H:%M:%S')
    flag = False
    while True:
        today = date.today()
        dt= today.strftime("%b %d")
        if flag:
            end = datetime.today().strftime('%H:%M:%S')
        print("Date time: ", dt, start, end)
        hex_string = get_hex(dt, start, end ) # get hex of the file chunk
        start = end
        flag = True
        key = get_current_date_string() # get the current date as key
        txid = c.publishfrom(from_addr, str_name, key, hex_string) # publish to multichain
        print("txid: ", txid)
        save_to_local_dir(txid,hex_string) # save to local directory after publishing
        save_to_firebase(txid, hex_string) # save to firebase for remote auditing
        tm = 10800
        print("Sleeping for " + str(tm) + " seconds " + "\n")
        time.sleep(tm) # file publishing periodically


def remote_audit_date(date, stream_name = "test"):
    key = date.strftime("%d/%m/%Y")
    print("Now auditing: ", key)
    list_tx_by_date = c.liststreamkeyitems(stream_name, key)  # get the list of all transactions
    for tx in list_tx_by_date:
        txid = tx['txid']
        multi_data = retrieve_hex_from_multichain(txid)  # get the multichain hex data
        firebase_data = retrieve_hex_from_firebase(txid)  # get the firebase hex data
        if multi_data == firebase_data:
            print(txid + " Mathced " + "\n")
        else:
            print(txid + " Not Matched " + "\n")


def remote_audit_timespan(stream_name = "test"):
    while True:
        dt = get_current_date_string()
        print(dt)
        list_tx_by_date = c.liststreamkeyitems(stream_name, dt)  # get the list of all transactions
        for tx in list_tx_by_date:
            txid = tx['txid']
            multi_data = retrieve_hex_from_multichain(txid)  # get the multichain hex data
            firebase_data = retrieve_hex_from_firebase(txid)  # get the local hex data
            if multi_data == firebase_data:
                print(txid + " Mathced " + "\n")
            else:
                print(txid + " Not Matched " + "\n")
        tm = 100
        print("Sleeping for " + str(tm) + " seconds " + "\n")
        time.sleep(tm)


def audit_by_date(dt, stream_name = "test"):
    print(" Auditing of date : ")
    key = dt.strftime("%d/%m/%Y")
    print(key)
    list_tx_by_date = c.liststreamkeyitems(stream_name, key)  # get the list of all transactions of this date
    for tx in list_tx_by_date:
        txid = tx['txid']
        if retrieve_hex_from_local(txid) == "File_Removed":
            print("File Not Found. Someone removed " + txid + " from the local directory!")
            continue
        match = match_file(txid)  # match the multichain file with the local file
        if match:
            print(txid + " Mathced " + "\n")
        else:
            print(txid + " Not Matched " + "\n")


def periodical_audit(dt, stream_name = "test"):  # local audit
    while True:
        audit_by_date(dt,stream_name)
        tm = 100
        print("Sleeping for " + str(tm)  + " seconds " + "\n")
        time.sleep(tm)


def convert_to_list(string):
    li = list(string.split(" "))
    return li

def get_password():
    # password_cmd = "openssl rand -base64 48"
    # out = subprocess.Popen(convert_to_list(password_cmd), # run openssl command using subprocess
    #                        stdout=subprocess.PIPE,
    #                        stderr=subprocess.STDOUT)
    # password, stderr = out.communicate()
    # password = password.decode().replace("\n", "") # strip the extra newline
    # return password  # get a random aes password

    from crypto_helper import get_random_key
    return get_random_key() # returns aes_key in bytes


def get_cipher_hex(filepath, password):
    cipherhex_cmd = "openssl enc -aes-256-cbc -in " + filepath + " -pass pass:" + password +" | xxd -p -c 99999 > out.txt"
    os.system(cipherhex_cmd)
    with open("out.txt", 'rb') as f:
        cipherhex = f.read()
    cipherhex = binascii.hexlify(cipherhex)
    return cipherhex # get the encoded file in publishable hex format


def save_pwd_to_local(txid,password):
    mkdir_ = "mkdir ~/.multichain/" + chainname + "/stream-passwords/"
    multi_dir = homedir + '/.multichain/' + chainname + '/stream-passwords/'
    if not os.path.exists(multi_dir):
        os.system(mkdir_)
    os.chdir(multi_dir)
    with open(str(txid) + ".txt", 'wb') as f:
        f.write(password)


def save_hex_to_local(txid,cipherhex):
    data = cipherhex
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/stream-data/'
    if not os.path.exists(file_path):
        os.system("mkdir " + file_path)
    with open(file_path + txid + ".txt", "wb") as file:
        file.write(data)  # save the uploaded file to local directory


def share_password(txid, aes_key, from_address, to_address):
    from crypto_helper import encrypt_aes_key
    stream_name = 'pubkeys'
    to_stream = "access"
    # txid2_pubkey = c.liststreampublisheritems(stream_name, to_address, True, 1)
    # txid2_pubkey = txid2_pubkey[0]['txid']  # txid of recipients public key
    vout = 0
    # pubkey_cmd = "multichain-cli " + chainname + " gettxoutdata " + txid2_pubkey + " " + str(
    #     vout) + " | tail -n 1 | xxd -p -r > /tmp/" + to_address + ".pem"  # check later
    # os.system(pubkey_cmd)  # retrieve the public key of the recipient from multichain
    recp_pubkey = retrieve_pubkey_for_address(to_address)
    # keycipher_cmd = "echo " + password + " | openssl rsautl -encrypt -inkey /tmp/" + to_address + ".pem -pubin | xxd -p -c 9999 > /tmp/" + to_address + ".txt"
    # os.system(keycipher_cmd)  # encrypt the password with recipient's public key
    encrypted_aes_key = encrypt_aes_key(recp_pubkey, aes_key)
    # with open("/tmp/" + to_address + ".txt", 'rb') as f:  # read encrypted password
    #     data = f.read()
    enc_aes_key_hex = binascii.hexlify(encrypted_aes_key)
    label = txid + "-" + to_address
    # print("Pwd enc: ", data)
    # enc_pwd_hex = binascii.hexlify(data)
    print("data pwd",enc_aes_key_hex)
    txid3_password = c.publishfrom(from_address, to_stream, label, enc_aes_key_hex)
    print("txid3_pass: ", txid3_password)
    print("Ok done....")


def confidential_publish(from_address,to_address, stream_name):
    from crypto_helper import encrypt
    from crypto_helper import get_random_key
    global homedir
    file_path = "/var/log/syslog"
    has_permission = c.listpermissions('send', from_address)
    if has_permission:
        aes_key = get_random_key() # generate a random password
        print(len(aes_key), aes_key)
        # cipherhex = get_cipher_hex(file_path,password) # get the cipherhex to publish
        with open(file_path, 'rb') as file:
            data = file.read()
        cipher_text = encrypt(aes_key, data)
        cipher_hex = binascii.hexlify(cipher_text)
        key = get_current_date_string()
        # print("cipher", cipher_hex)
        txid = c.publishfrom(from_address, stream_name, key, cipher_hex)  # publish the encrypted log data
        print(txid)
        save_pwd_to_local(txid, aes_key) # save the aes-key to local directory
        save_to_local_dir(txid,cipher_hex) # save cipherhex to local directory
        pubkey_stream = 'pubkeys'
        c.subscribe(pubkey_stream)
        # share the encrypted password to multichain from where recipient can retrieve
        share_password(txid,aes_key,from_address,to_address)
        return "File published at txid " + txid
    else:
        return "This address: " + from_address + " doesn't have permission to publish"


def decrypt_confidential_data(txid, address):
    from crypto_helper import decrypt, decrypt_aes_key
    stream_name_item = 'items'
    stream_name_access = 'access'
    label = txid + "-" + address
    access_stream_details = c.liststreamkeyitems(stream_name_access, label) # get the access stream labeled by label
    stream_data_hex = access_stream_details[0]['data'] # get the hex of encrypted aes key
    enc_aes_key = binascii.unhexlify(stream_data_hex.encode()) # get the aes-key
    file_path = os.environ['HOME'] + '/.multichain/' + chainname + '/stream-privkeys/'
    os.chdir(file_path)
    with open(address+".pem", 'rb') as file:
        privkey = file.read()
    print(len(enc_aes_key),type(enc_aes_key), enc_aes_key)
    aes_key = decrypt_aes_key(privkey, enc_aes_key)
    print(len(aes_key), type(aes_key), aes_key)
    cipher_text_hex = c.gettxoutdata(txid, 0)
    cipher_text = binascii.unhexlify(cipher_text_hex.encode())
    decrypted_data = decrypt(aes_key, cipher_text)
    print(decrypted_data)
    return decrypted_data

# publishing_thread = threading.Thread(target=publish_periodically, args=(addresses[0],"test",))
# publishing_thread.start()
# confidential_publishing_thread = threading.Thread(target=confidential_publish, args=(addresses[0],"",))
# confidential_publishing_thread.start()

# auditing_thread = threading.Thread(target=remote_audit_timespan, args=())
# auditing_thread.start()


posts =  {
        'chainname': chainname,
        'address' : addresses[0],
        'rpchost': rpchost,
        'stream': 'pubkeys'
    }


def get_node(str):
    li = []
    crt_addresses = client.listpermissions(str)
    for cl in crt_addresses:
        if cl['address'] in addresses:
            li.append(cl['address'])
    return li
# get list of addresses of particular permission str


def get_permission_dict(addresses):
    list_permissions = c.listpermissions()
    dict_permission = {}
    for address in addresses:
        per = []
        for li in list_permissions:
            if li['address'] == address:
                per.append(li['type'])
        dict_permission[address] = per
    return dict_permission
# get all the permissions of particular address as a dictionary


def get_current_permission():
    current_permissions = c.listpermissions()
    list_addresses = []
    dict_permission = {}
    for permission in current_permissions:
        addr = permission['address']
        if addr in list_addresses:
            continue
        list_addresses.append(addr)
        li = []
        for per in current_permissions:
            if per['address'] == addr:
                li.append(per['type'])

        dict_permission[addr] = li
    return list_addresses,dict_permission
# get all the permissions of all addresses


def get_unsubscribed_streams():  # returns the list of all unsubscribed stream
    li = []
    list_streams = c.liststreams('*',True)
    for stream in list_streams:
        if not stream['subscribed']:
            li.append(stream['name'])
    return li


# confidentially publish

# def get_admins():
#     adminaddresses = []
#     admins = c.listpermissions("admin")
#     for admin in admins:
#         if admin['address'] in addresses:
#             adminaddresses.append(admin['address'])
#     return adminaddresses


def comma_separated(li):
    st = str(li)
    st = st.replace("[", "")
    st = st.replace("]", "")
    st = st.replace("'", "")
    # st = "\"" + st + "\""
    st = st.replace(" ","")
    return st
# convert to comma separated string


@app.route('/')
def homepage():
    return render_template('home.html')


@app.route('/info.html')
def info_page():
    return render_template('node_info.html', node_info = c.getinfo(), peers_info = c.getpeerinfo(), addresses = c.getaddresses(), permissions = get_permission_dict(c.getaddresses()))


@app.route('/connect.html')
def connect_page():
    return render_template('connect.html')


@app.route('/view-streams.html', methods = ['GET','POST'])
def viewstream_page():
    return render_template('view-streams.html', list_streams = c.liststreams('*',True), addresses = c.getaddresses(),  permissions = get_permission_dict(c.getaddresses()))


@app.route('/stream-details.html', methods = ['GET','POST'])
def view_stream_details():
    if request.method == "POST":
        stream_name = request.form['stream-name']
    return (stream_name)


@app.route('/connect', methods = ['GET','POST'])
def connect():
    if request.method == "POST":
        c_name = request.form['c-name']
        ip = request.form['ip']
        port = request.form['port']
    cmd = "multichaind " + c_name + "@" + ip + ":" + port
    print("Connect command : ", cmd)
    os.system(cmd)
    return "Node connected"


@app.route('/permissions.html')
def permissions_page():
    list_addresses, dict_permissions = get_current_permission()
    return render_template('permissions.html', adminaddresses = get_node("admin"), list_addresses = list_addresses, dict_permissions = dict_permissions)


@app.route('/permissions', methods=['GET','POST'])
def permissions():
    if request.method == "POST":
        admin = request.form['admin']
        to_addr = request.form['toaddress']
        permission_list = request.form.getlist('permissions')
        operation = request.form.getlist('grant')
    permission_list = comma_separated(permission_list)
    print("Permission",permission_list)
    print(type(permission_list))
    if operation[0] == "grant":
        c.grantfrom(admin, to_addr,permission_list)
        return permission_list + " permissions granted from " + admin + " to " + to_addr
    elif operation[0] == "revoke":
        c.revokefrom(admin, to_addr, permission_list)
        return permission_list + " permissions revoked from " + admin + " to " + to_addr


@app.route('/generate.html')
def generate_page():
    return render_template('key_generation.html', addresses = get_node("send"), streams = c.liststreams('*',True))


@app.route('/generate', methods=['POST', 'GET'])
def generate():
    global homedir
    if request.method == 'POST':
        address = request.form['address']
        stream_name = request.form['stream']
        multi_dir = homedir + '/.multichain/' + chainname + '/stream-privkeys/'

        from crypto_helper import generate_rsa_key_pair
        privkey, pubkey = generate_rsa_key_pair(2048)

        stream_list = c.liststreams()
        for stream in stream_list:
            if stream['name'] == stream_name:
                if not stream['subscribed']:
                    c.subscribe(stream_name)

        publisher_list = c.liststreampublishers(stream_name)
        flag = False
        for publisher in publisher_list:
            if publisher['publisher'] == address:
                flag = True
        if flag:
            # retrieve_pubkey_for_address(address)
            return "Public Key Already Published for this address" + ': ' + address
        if not os.path.exists(multi_dir):
            os.makedirs(multi_dir)
        os.chdir(multi_dir)
        # write the corresponding private key to the file
        filename = address + '.pem'
        with open(filename, 'wb') as file:
            file.write(privkey)
        os.chdir(os.environ['HOME'])

        pubkey_hex = binascii.hexlify(pubkey)
        has_permission = c.listpermissions('send', address)
        if has_permission:
            c.publishfrom(address, stream_name, address, pubkey_hex)
            print(pubkey_hex)
            print(address, stream)
            return "Public key published for this address: " + address
        else:
            return "This address: " + address + " doesn't have permission to publish"
        return render_template("home.html")


def retrieve_pubkey_for_address(address):
    stream_name = 'pubkeys'
    query = c.liststreamkeyitems(stream_name, address)
    pubkey_hex = query[0]['data']
    print(type(pubkey_hex), pubkey_hex)
    pubkey = binascii.unhexlify(pubkey_hex.encode())
    print(pubkey)
    return pubkey # returns pubkey in byte


@app.route('/publish.html', methods= ['GET','POST'])
def publish_page():
    return render_template('publish.html', addresses = c.getaddresses(), streams = c.liststreams('*',True), peers = c.getpeerinfo())


@app.route('/publish', methods= ['GET','POST'])
def publish():
    global homedir
    if request.method == "POST":
        from_address = request.form['fromaddress']
        test_stream = request.form['stream']
    # today = date.today()
    # dt = today.strftime("%b %d")
    # hex_string = get_hex(dt, "00:00:00", "23:59:59")  # get the hex representation of the file to publish
    has_permission = c.listpermissions('send', from_address) # check permission
    if has_permission:
        # dt_string = get_current_date_string() # get the current date
        # print("")
        # txid = c.publishfrom(from_address, test_stream, dt_string, hex_string)
        # save_to_local_dir(txid, hex_string) # save data to local directory after publishing
        # save_to_firebase(txid,hex_string)  # save to firebase for remote auditing
        publishing_thread = threading.Thread(target=publish_periodically, args=(from_address,test_stream,))
        publishing_thread.start()
        return "Periodical Publish started successfully"
    else:
        return from_address + " doesn't have not send permission"


@app.route('/publish-con.html', methods= ['GET','POST'])
def publish_con_page():
    return render_template('publish-con.html', addresses = c.getaddresses(), streams = c.liststreams('*',True), peers = c.getpeerinfo())


@app.route('/publish-con', methods=['GET','POST'])
def publish_con():
    if request.method == "POST":
        from_address = request.form['fromaddress']
        to_address = request.form['toaddress']
        stream_name = request.form['stream']
    result = confidential_publish(from_address, to_address, stream_name)
    return result


@app.route('/retrieve', methods = ['GETS','POST'])
def retrieve():
    c.subscribe("items","access")


@app.route('/audit-by-txid.html')
def audit_by_txid_page():
    return render_template('audit-by-txid.html', addresses = get_node("admin"))


@app.route('/remote-audit-by-txid.html')
def remote_audit_by_txid_page():
    return render_template('remote-audit-by-txid.html', addresses = get_node("admin"))


@app.route('/audit-by-txid', methods= ['GET','POST'])
def audit_by_txid():
    global homedir
    if request.method == "POST":
        auditor_addr = request.form['auditoraddress']
        txid = request.form['txid']

    if retrieve_hex_from_multichain(txid) == "Wrong_txid":
        return "Transaction id is invalid...Please provide the correct one!"
    elif retrieve_hex_from_local(txid) == "File_Removed":
        return "File Not Found. Someone removed " + txid + " from the local directory!"
    match = match_file(txid) # matching multichain file with local file
    str_data = rebuild_multichain_file(txid)
    if match: # comparing local and multi hex data
        return "File Matched" + "\n" + str_data
    else:
        return "Not Matched" + "\n"


@app.route('/remote-audit-by-txid', methods= ['GET','POST'])
def remote_audit_by_txid():
    global homedir
    if request.method == "POST":
        auditor_addr = request.form['auditoraddress']
        txid = request.form['txid']

    if retrieve_hex_from_multichain(txid) == "Wrong_txid":
        return "Transaction id is invalid...Please provide the correct one!"
    multi_data = retrieve_hex_from_multichain(txid)  # get the multichain hex data
    firebase_data = retrieve_hex_from_firebase(txid)  # get the firebase hex data
    if multi_data == firebase_data:
        return txid + " Mathced "
    else:
        return txid + "Not Mathced"


@app.route('/audit-by-date.html')
def audit_by_date_page():
    return render_template('audit-by-date.html', addresses = get_node("admin"), streams = c.liststreams('*',True) )


@app.route('/remote-audit-by-date.html')
def remote_audit_by_date_page():
    return render_template('remote-audit-by-date.html', addresses = get_node("admin"), streams = c.liststreams('*',True) )


@app.route('/audit-by-date', methods= ['GET','POST'])
def audit_date():
    global homedir
    if request.method == "POST":
        start_date = request.form['start']
        end_date = request.form['end']
        stream_name = request.form['stream']

    start_date = convert_str_to_date(start_date)
    end_date = convert_str_to_date(end_date)
    delta = timedelta(days=1)
    while start_date <= end_date:  # loop through start date till end date
        # remote_audit(start_date)
        audit_by_date(start_date, stream_name)
        start_date += delta
    print("Finished Auditing")
    return "Audit Started Successful"


@app.route('/remote-audit-by-date', methods= ['GET','POST'])
def rm_audit_date():
    global homedir
    if request.method == "POST":
        start_date = request.form['start']
        end_date = request.form['end']
        stream_name = request.form['stream']

    start_date = convert_str_to_date(start_date)
    end_date = convert_str_to_date(end_date)
    delta = timedelta(days=1)
    while start_date <= end_date:  # loop through start date till end date
        # remote_audit(start_date)
        remote_audit_date(start_date, stream_name)
        start_date += delta
    print("Finished Auditing")
    return "Audit Started Successful"

def convert_str_to_date(str):
    # takes 10/23/2019 as input, returns a date object with date(2019, 10, 23)
    str = str.split("/")
    return date(int (str[2]), int (str[0]), int (str[1]))


@app.route('/retrieve-by-txid.html', methods = ['GET', 'POST'])
def retrieve_by_txid_page():
    return render_template('retrieve-by-txid.html')


@app.route('/retrieve-by-txid', methods = ['GET', 'POST'])
def retrieve_by_txid():
    if request.method == "POST":
        txid = request.form['txid']
    res = rebuild_multichain_file(txid)
    return res


@app.route('/retrieve-by-date.html')
def retrieve_by_date_page():
    return render_template('retrieve-by-date.html', streams = c.liststreams('*',True) )


@app.route('/retrieve-by-date', methods= ['GET','POST'])
def retrieve_date():
    global homedir
    max_data_byte = 50
    if request.method == "POST":
        start_dt = request.form['start']
        end_dt = request.form['end']
        stream_name = request.form['stream']
    start_date = convert_str_to_date(start_dt)
    end_date = convert_str_to_date(end_dt)
    delta = timedelta(days=1)
    li = []
    while start_date <= end_date:
        key = start_date.strftime("%d/%m/%Y")
        print(key)
        list_tx_by_date = c.liststreamkeyitems(stream_name, key)  # get the list of all transactions of today
        for tx in list_tx_by_date:
            dic = {}
            dic['txid'] = tx['txid']
            dic['publisher'] = tx['publishers'][0]
            dic['key'] = tx['keys'][0]
            hex_data = c.gettxoutdata(tx['txid'], 0, max_data_byte)  # returns first 50 byte of data
            data = hex_to_string(hex_data)
            dic['data'] = data
            li.append(dic)
        start_date += delta
    return render_template('transaction_table.html', items=li, stream_name=stream_name , start_date = start_dt, end_date = end_dt)


@app.route('/view-con.html')
def view_file_page():
    return render_template('view-file.html',addresses = get_node("admin"))


@app.route('/view-file.html', methods=['GET','POST'])
def view_file():
    global homedir
    if request.method == "POST":
        address = request.form['address']
        txid = request.form['txid']

    if retrieve_hex_from_multichain(txid) == "Wrong_txid":
        return "Transaction id is invalid...Please provide the correct one!"
    res = decrypt_confidential_data(txid,address)
    # res = rebuild_multichain_file(txid)
    return res


@app.route('/create-stream.html')
def create_stream_page():
    return render_template('create-stream.html', addresses = get_node("create"))


@app.route('/create-stream', methods = ['GET', 'POST'])
def create_stream():
    if request.method == "POST":
        from_addr = request.form['fromaddress']
        str_name = request.form['streamname']
    c.createfrom(from_addr,"stream",str_name,False)
    return "Stream " + str_name + " is created by : "+ from_addr


@app.route('/retrieve-by-stream.html', methods= ['GET','POST'])
def view_item_page():
    return render_template('view-stream.html', streams = c.liststreams('*',True))


@app.route('/view-stream', methods=['GET', 'POST'])
def view_stream():
    if request.method == "POST":
        stream_name = request.form['stream']

    return render_template('transaction_table.html', items = get_items_by_stream(stream_name), stream_name = stream_name)


def get_items_by_stream(stream_name):       # get short information of all items in a stream
    max_data_byte = 50
    c.subscribe(stream_name)
    item_list = c.liststreamitems(stream_name)
    li = []

    for item in item_list:
        dic = {}
        dic['txid'] = item['txid']
        dic['publisher'] = item['publishers'][0]
        dic['key'] = item['keys'][0]
        hex_data = c.gettxoutdata(item['txid'], 0, max_data_byte) # returns first 50 byte of data
        data = hex_to_string(hex_data)
        dic['data'] = data
        li.append(dic)
    return li  # returns a list of dict


@app.route('/subscribe.html', methods = ['GET'])
def subscribe_page():
    return render_template('subscribe.html', addresses = get_node("admin"), unsubscribed_list = get_unsubscribed_streams() )


@app.route('/subscribe', methods = ['POST'])
def subscribe():
    if request.method == "POST":
        address = request.form['address']
        stream_name = request.form['stream']
    c.subscribe(stream_name)
    return stream_name + " is subscribed by the address: " + address


if __name__ == '__main__':

    app.run()
