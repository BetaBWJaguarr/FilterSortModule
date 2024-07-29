import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

def send_email(subject, recipient, body):
    smtp_server = 'localhost'
    smtp_port = 1025
    sender_email = 'no-reply@yourdomain.com'

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = formataddr(('No Reply', sender_email))
    msg['To'] = recipient

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(sender_email, recipient, msg.as_string())
        return True
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
    except Exception as e:
        print(f"Error sending email: {e}")
    return False
