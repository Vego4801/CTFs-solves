import flask


app = flask.Flask(__name__)
# mmh, a secret
flag = "CCIT{REDACTED}"

# this site is still on construction.
# As you can see there is litteraly nothing here


@app.route('/')
def index():
    return flask.render_template('index.html')


if __name__ == '__main__':
    app.run()
