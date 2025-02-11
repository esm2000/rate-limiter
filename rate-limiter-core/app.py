from flask import Flask
app = Flask(__name__)

@app.route('/')
def default():
    return 'rate-limiter-core'


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=3000)