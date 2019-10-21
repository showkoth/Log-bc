import binascii
import sys
from datetime import datetime, date, timedelta
import time

from flask import Flask,render_template,request
import mcrpc
import subprocess
from Crypto.Cipher import AES
import os
import pyrebase


def find_chunk_size(dt, start):
    time_mask = "%b %d %H:%M:%S"
    os.chdir(os.environ['HOME'])
    # f_name = "test.txt"
    f_name = "/home/showkot/out.txt"
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

find_chunk_size("Oct 01","00:00:00")

    # print(data)
    # print(data.__sizeof__())
    # return data
