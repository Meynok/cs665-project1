import sqlite3
from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


# Database Helper Function
def get_db_connection():
    connection = sqlite3.connect('fake_db.db')
    connection.row_factory = sqlite3.Row
    return connection


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)