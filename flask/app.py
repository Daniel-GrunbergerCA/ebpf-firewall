from flask import Flask, render_template, request, jsonify
import json
import os

app = Flask(__name__)

heading = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "status")

data = [
    
]

@app.route("/")
def table():
    return render_template("table.html", headings=heading, data=data)

@app.route('/add',methods = ['POST'])
def add():
    content =request.get_json()
    try:
        src_ip  = content['src_ip']
        src_port =  content['src_port']
        dst_ip = content['dst_ip']
        dst_port = content['dst_port']
        protocol  = content['protocol']
        status  = content['status']
    except:
        print('error with json data')
    data.append((src_ip, src_port, dst_ip, dst_port, protocol, status))  
    return render_template("table.html", headings=heading, data=data)

