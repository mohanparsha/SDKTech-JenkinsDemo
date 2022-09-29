# Importing Module Libraries

from __future__ import print_function
import boto3
import os
import sys
import json
from urllib.parse import unquote_plus
import logging
from botocore.exceptions import ClientError
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import date
import requests

# Create a new S3 Resource.
s3_client = boto3.client('s3')

# Create a new SSM Resource.
ssm_client = boto3.client('ssm')

# Initializing Variables with Parameter Store
parameter = ssm_client.get_parameter(
    Name=os.environ.get('ENV_NAME') +
    '-target-bucket',
    WithDecryption=True)
trgt_bucket = parameter['Parameter']['Value']

parameter = ssm_client.get_parameter(
    Name=os.environ.get('ENV_NAME') +
    '-target-path',
    WithDecryption=True)
trgt_path = parameter['Parameter']['Value']

# Making connection with AWS secret manager ####
sec_client = boto3.client('secretsmanager')

response = sec_client.get_secret_value(
    SecretId=os.environ.get('ENV_NAME') + '-smtp-settings'
)

# Parsing JSON String to dictionary  #####
secret = json.loads(response['SecretString'])

# Getting SMTP Credentials from secret manager ####
smtp_server = secret[os.environ.get('ENV_NAME') + '-smtp_server']
smtp_port = secret[os.environ.get('ENV_NAME') + '-smtp_port']
smtp_send_address = secret[os.environ.get('ENV_NAME') + '-send_address']
smtp_send_password = secret[os.environ.get('ENV_NAME') + '-send_password']
smtp_receive_address = secret[os.environ.get('ENV_NAME') + '-receive_address']

# Email Address and the Passcode
receive_address = smtp_receive_address
send_address = smtp_send_address
send_pass = smtp_send_password

# Set Current Date
current_date = date.today()


def lambda_handler(event, context):

    # Enable Logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Initializing Email Body MIME
    message = MIMEMultipart()
    message['From'] = send_address
    message['To'] = receive_address
    mail_content = " "

    # Print Source Event
    logger.info("********    S3 Event Source Details  ********")
    src_event = event['Records'][0]['body']
    evnt_dict = json.loads(src_event)
    logger.info("Event: {}".format(evnt_dict))

    # Define Source Bucket and Object Key
    logger.info("********    Source Bucket and Object Key Details  ********")
    src_bucket = evnt_dict['Records'][0]['s3']['bucket']['name']
    object_key = unquote_plus(evnt_dict['Records'][0]['s3']['object']['key'])
    version_id = unquote_plus(
        evnt_dict['Records'][0]['s3']['object']['versionId'])
    copy_source = {'Bucket': src_bucket, 'Key': object_key}

    # Print Values
    logger.info("Source Bucket : {}".format(src_bucket))
    logger.info("Object Key : {}".format(object_key))
    logger.info("Version ID of Object : {}".format(version_id))
    logger.info("Copy Source : {}".format(copy_source))

    # Business logic for Filename modification
    src_keyname = object_key.rsplit('/', 3)
    src_filename = src_keyname[3]

    trgt_filename = re.sub("[^A-Za-z0-9/_\\-.]", "", src_filename)
    dst_path = trgt_path + '/' + current_date.strftime("%Y/%m/%d/") + os.path.splitext(
        trgt_filename)[0] + os.path.splitext(trgt_filename)[1]
    logger.info("Destination Path : {}".format(dst_path))

    # Create SMTP Server Resource and Authenticate
    email_server = smtplib.SMTP(smtp_server, smtp_port)
    email_server.ehlo()
    email_server.starttls()
    email_server.login(send_address, send_pass)

    # Slack Webhook URL
    slack_url = " "

    # S3 API call for file object upload
    try:
        s3_client.copy_object(Bucket=trgt_bucket,
                              Key=dst_path, CopySource=copy_source)
        logger.info(
            "File {} copied to Destination Bucket {} as {} ".format(
                src_filename, trgt_bucket, trgt_filename))

        # Construct Email Message
        message['Subject'] = 'File Upload Status - Successful'
        mail_content = "'File %s copied to Destination S3 Bucket %s as %s'" % (
            src_filename, trgt_bucket, trgt_filename)
        message.attach(MIMEText(mail_content, 'plain'))
        email_text = message.as_string()
        email_server.sendmail(send_address, receive_address, email_text)

        # Construct Slack WebHook Payload
        slack_paylaod_string = (
            "'File Uploaded to Destination S3 Bucket %s as %s'" %
            (trgt_bucket, trgt_filename))
        slack_payload = {
            "username": "FCI-NotificationBot",
            "icon_emoji": ":zap:",
            "attachments": [
                {
                    "color": "#7bf538",
                    "fields": [
                        {
                            "title": "File Upload Status -Successful",
                            "value": slack_paylaod_string,
                        }
                    ]
                }
            ]
        }
        slack_byte_length = str(sys.getsizeof(slack_payload))
        headers = {
            'Content-Type': "application/json",
            'Content-Length': slack_byte_length}
        slack_response = requests.post(
            slack_url,
            data=json.dumps(slack_payload),
            headers=headers)
        if slack_response.status_code != 200:
            raise Exception(response.status_code, response.text)

    except ClientError as err:
        logging.error(err)
        logger.error("File {} copy to Destination Bucket {} FAILED ".format(
            src_filename, trgt_bucket))

        # Construct Email Message
        message['Subject'] = 'File Upload Status - Failed'
        mail_content = "'File %s Upload to Destination S3 Bucket %s FAILED'" % (
            src_filename, trgt_bucket)
        message.attach(MIMEText(mail_content, 'plain'))
        email_text = message.as_string()
        email_server.sendmail(send_address, receive_address, email_text)

        # Construct Slack WebHook Payload
        slack_paylaod_string = (
            "'File %s Upload to Destination S3 Bucket %s FAILED'" %
            (src_filename, trgt_bucket))
        slack_payload = {
            "username": "FCI-NotificationBot",
            "icon_emoji": ":zap:",
            "attachments": [
                {
                    "color": "#f53854",
                    "fields": [
                        {
                            "title": "File Upload Status -Failed",
                            "value": slack_paylaod_string,
                        }
                    ]
                }
            ]
        }
        slack_byte_length = str(sys.getsizeof(slack_payload))
        headers = {
            'Content-Type': "application/json",
            'Content-Length': slack_byte_length}
        slack_response = requests.post(
            slack_url,
            data=json.dumps(slack_payload),
            headers=headers)
        if slack_response.status_code != 200:
            raise Exception(response.status_code, response.text)

    logger.info("Closing the Email Server Connection")
    email_server.close()
    return

