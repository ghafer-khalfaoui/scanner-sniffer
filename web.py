from flask import Flask , render_template , request 
import threading
from port_scanner import runner
from shared import open_ports 

app = Flask(__name__)
@app.route("/",methods=["GET" , "POST" ])
def index():
    if request.method == "POST":
        target = request.form["target"]
        start = int(request.form["start"])
        end = int(request.form["end"])

        open_ports.clear()
        scan_thread = threading.Thread(target=runner,args=(target, range(start, end + 1)) )
        scan_thread.start()

    return render_template("index.html", ports=sorted(open_ports))

app.run(host="0.0.0.0", port=5000)