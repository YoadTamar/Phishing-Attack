"""
this file contains the implementations of email spoofer,
with the correct usage of SMTP server, it can be used for email spoofing.

:authors: Lior Vinman & Yoad Tamar

:since: 11/06/2023
"""


import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# credentials for SMTP server
(USERNAME, PASSWORD) = ("", "")

# address of SMTP server
(SERVER, PORT) = ("", 0)


def send_email(sender_email: str,
               sender_name: str,
               receiver_email: str,
               receiver_name: str,
               subject: str,
               content: str,
               attachment_paths: list[str]) -> None:
    """
    This function sends the email through the SMTP server.

    :param sender_email: Source email (might be spoofed).
    :param sender_name: (Source) email sender name (might be spoofed).
    :param receiver_email: Destination email.
    :param receiver_name: (Destination) email receiver name.
    :param subject: Email's subject.
    :param content: Email's contents.
    :param attachment_paths: List of file paths for attachments.
    """
    
    # setting the email's mime (sender/receiver/subject...)
    message = MIMEMultipart()

    message["From"] = f"{sender_name} <{sender_email}>"

    message["To"] = f"{receiver_name} <{receiver_email}>"

    message["Subject"] = subject

    message.attach(MIMEText(content, "plain"))

    # attaching files into email
    for attachment_path in attachment_paths:

        with open(attachment_path, "rb") as attachment_file:

            # setting the file parts into mime
            part = MIMEBase("application", "octet-stream")

            part.set_payload(attachment_file.read())

            encoders.encode_base64(part)

            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {attachment_path}",
            )

            message.attach(part)

    try:

        # connecting to the SMTP server, and sending the constructed email
        with smtplib.SMTP(SERVER, PORT) as server:
            
            # using TLS for security connection
            server.starttls()

            # logining into SMTP server
            server.login(USERNAME, PASSWORD)

            # sending the email through the server
            server.sendmail(USERNAME, receiver_email, message.as_string())

            # closing session with the server
            server.quit()

    except Exception as e:

        print(f"Error: {e}")

        sys.exit(1)


def main():

    # reading email contents and subject from external files
    with open("email_content", "r") as f1, open("email_subject", "r") as f2:

        # reading the contents of message, should be HTML(!)
        contents = f1.read()

        # email using `<br/>` so we dont need double spaces.
        contents = contents.replace("\n", "")

        # reading the contents of the subject
        subject = f2.read()

        # sending the email
        send_email("",
                   "",
                   "",
                   "",
                   subject,
                   contents,
                   [])

    print("Email has been sent.")


if __name__ == "__main__":
    main()
