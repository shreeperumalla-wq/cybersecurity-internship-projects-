# main.py
from flask import Flask, render_template, request, redirect, url_for
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import webbrowser
import time
import threading
import os


# Function to send phishing email
def send_phishing_email(to_address, subject, body):
    from_address = "kalpanamaram2005@gmail.com"
    password = "rfchdhlfxvpqwiha"

    msg = MIMEMultipart()
    msg['From'] = from_address
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_address, password)
        text = msg.as_string()
        server.sendmail(from_address, to_address, text)
        server.quit()
        print(f"Phishing email sent to {to_address}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to simulate user interaction
def simulate_user_interaction():
    time.sleep(5)  # Wait for the user to open the email client
    print('Opening suspicious email...')
    time.sleep(1)
    print('Clicking on the link...')

# Function to run the Flask server
def run_flask_server():
    import subprocess
    subprocess.run(["python", "flask_server.py"])

# Example usage
if __name__ == '__main__':
    phishing_email_subject = "Action Required: Update Your Account Information"
    phishing_email_body = """
    Dear User,

    We noticed some unusual activity in your account. 
    Please update your account information by clicking the link below:

    http://localhost:5000

    Thank you,
    Security Team
    """

    # Send the phishing email
    send_phishing_email("kalpanamaram2005@gmail.com", phishing_email_subject, phishing_email_body)

    # Start the Flask server in a separate thread
    server_thread = threading.Thread(target=run_flask_server)
    server_thread.daemon = True
    server_thread.start()

    # Simulate user interaction
    simulate_user_interaction()

    # Open the phishing page in the default web browser
    time.sleep(2)  # Ensure the server has started
    webbrowser.open("http://localhost:5000")
