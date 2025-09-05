# flask_server.py
from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)

# Get the directory of the current script and use it to create an absolute path to users.txt
current_dir = os.path.dirname(os.path.abspath(__file__))
USER_FILE = os.path.join(current_dir, 'users.txt')

def write_user(username, password):
    # Create the users.txt file if it doesn't exist
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, 'w') as file:
            pass
    
    # Append new user credentials to users.txt
    with open(USER_FILE, 'a') as file:
        file.write(f'{username},{password}\n')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Write the user credentials to users.txt
        write_user(username, password)
        # Redirect to dashboard or any other page after login
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return 'Welcome to the Dashboard!'

if __name__ == '__main__':
    app.run(debug=True)
