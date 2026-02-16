from flask import Flask, render_template, request, jsonify
import threading
from port_scanner import runner
from sniffer import start_sniffing
from shared import open_ports, scanned_ports

app = Flask(__name__)


t_sniff = threading.Thread(target=start_sniffing, daemon=True)
t_sniff.start()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        start = int(request.form.get("start"))
        end = int(request.form.get("end"))

        
        open_ports.clear()
        scanned_ports.clear()

        
        t_scan = threading.Thread(
            target=runner,
            args=(target, range(start, end + 1)),
            daemon=True
        )
        t_scan.start()
        
        return jsonify({"status": "scanning", "target": target})

    return render_template("index.html")

@app.route("/api/results")
def results():
    return jsonify({"open_ports": sorted(list(open_ports))})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

