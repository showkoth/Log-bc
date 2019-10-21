import binascii

from flask import Flask,render_template,request
from Savoir import Savoir
import mcrpc
import subprocess
from Crypto.Cipher import AES
import os
from Crypto.PublicKey import RSA
import test

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template('home.html')


@app.route('/connect.html')
def connect_page():
    return render_template('connect.html')


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


if __name__ == '__main__':
    app.run()
