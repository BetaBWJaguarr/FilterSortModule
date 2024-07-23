import smtplib
from email.mime.text import MIMEText

def send_email(subject, recipient, body):
    try:
        smtp_server = 'localhost'
        smtp_port = 1025

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'no-reply@yourdomain.com'
        msg['To'] = recipient

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail('no-reply@yourdomain.com', recipient, msg.as_string())

        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
