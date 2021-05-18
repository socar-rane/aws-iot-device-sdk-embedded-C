from flask import Flask
import argparse
import sys, os, signal, time

app = Flask(__name__)

@app.route('/')
def home():
    os.system("./mqtt_demo_mutual_auth -f &")
    return "hello World"

def add_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", required=True, action='store', dest="port", type=int, help="enter port number")
    args = parser.parse_args()
    return args

def exception_handler():
    sys.exit()

if __name__ == '__main__':
    args = add_arguments()
    signal.signal(signal.SIGINT, exception_handler)
    app.run(debug=True, host='0.0.0.0', port=args.port)