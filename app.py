from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('store/index.html')


@app.route('/about')
def about():
    return render_template('store/about.html')


if __name__ == '__main__':
    app.run(debug=True)
