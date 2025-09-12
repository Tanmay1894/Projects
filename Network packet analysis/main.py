from flask import Flask,render_template

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
# from flask import Flask, render_template, jsonify
# from analyzer import run_sniffer_in_background, packets_buffer

# app = Flask(__name__)

# # Start sniffer thread when app starts
# run_sniffer_in_background()

# @app.route("/")
# def index():
#     return render_template("index.html")

# @app.route("/get_packets")
# def get_packets():
#     return jsonify(packets_buffer[-20:])  # send last 20 packets

# if __name__ == "__main__":
#     app.run(debug=True)
