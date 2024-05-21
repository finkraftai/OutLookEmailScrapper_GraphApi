from flask import Flask, redirect, session, url_for, request, jsonify, send_file
import requests
import secrets
import hashlib
import base64
import os
import csv
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_value'

@app.route('/')
def homepage():
    return redirect(url_for('login'))

@app.route('/logins')
def login():
    code_verifier = secrets.token_urlsafe(64)
    session['code_verifier'] = code_verifier
    code_challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode()
    
    callback = url_for('authorized', _external=True, _scheme='https')
    authorization_url = ('https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
                         '?client_id={CLIENT_ID}&response_type=code&redirect_uri={CALLBACK_URL}'
                         '&response_mode=query&scope=openid+offline_access+User.Read+Mail.Read'
                         '&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256'.format(
                             CLIENT_ID='d28671a0-5975-4d30-b7bc-301172b69142',
                             CALLBACK_URL=callback,
                             CODE_CHALLENGE=code_challenge))
    return redirect(authorization_url)

@app.route('/logins/authorized')
def authorized():
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')
    callback = url_for('authorized', _external=True, _scheme='https')

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {
      'grant_type': 'authorization_code',
      'client_id': 'd28671a0-5975-4d30-b7bc-301172b69142',
      'client_secret': 'xvu8Q~ystX5eZuJlS-_W8XfsbnlGzpCZoCVmzdkW',
      'code_verifier': code_verifier,
      'redirect_uri': callback,
      'code': code,
      'scope': 'openid offline_access User.Read Mail.Read'
    }

    response = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', headers=headers, data=data)
    if response.status_code == 200:
        session['access_token'] = response.json()['access_token']
        return redirect(url_for('display_emails'))
    else:
        return jsonify(response.json())

@app.route('/display_emails')
def display_emails():
    if 'access_token' in session:
        # start_date_str = request.args.get('start_date')
        # end_date_str = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))

        start_date_str = '2024-05-20'  # Default start date
        end_date_str = '2024-05-22'    # Default end date

        if not start_date_str:
            start_date_str = end_date_str

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        
        headers = {
            'Authorization': 'Bearer ' + session['access_token'],
        }

        response = requests.get('https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages', headers=headers)
        if response.status_code == 200:
            emails = response.json()
            filtered_emails = []

            # Prepare CSV file
            os.makedirs('output', exist_ok=True)
            csv_path = os.path.join('output', 'emails.csv')
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['From', 'To', 'Subject', 'Date', 'no_of_attachments', 'no_of_attachments_downloaded']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for email in emails.get('value', []):
                    received_date = datetime.strptime(email['receivedDateTime'][:10], '%Y-%m-%d')
                    if start_date <= received_date <= end_date:
                        from_email = email['from']['emailAddress']['address']
                        to_email = email['toRecipients'][0]['emailAddress']['address']
                        subject = email.get('subject')
                        date = email['receivedDateTime']

                        no_of_attachments = 0
                        no_of_attachments_downloaded = 0

                        if email.get('hasAttachments'):
                            message_id = email['id']
                            attachments_response = requests.get(
                                f'https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments', headers=headers)
                            if attachments_response.status_code == 200:
                                attachments = attachments_response.json().get('value', [])
                                downloaded_attachments = []
                                for attachment in attachments:
                                    no_of_attachments += 1
                                    attachment_id = attachment['id']
                                    attachment_content_response = requests.get(
                                        f'https://graph.microsoft.com/v1.0/me/messages/{message_id}/attachments/{attachment_id}/$value',
                                        headers=headers,
                                        stream=True
                                    )
                                    if attachment_content_response.status_code == 200:
                                        attachment_content = attachment_content_response.content
                                        attachment_name = attachment['name']
                                        attachment_path = os.path.join('attachments', attachment_name)
                                        os.makedirs('attachments', exist_ok=True)
                                        with open(attachment_path, 'wb') as file:
                                            file.write(attachment_content)
                                        downloaded_attachments.append(attachment_path)
                                        no_of_attachments_downloaded += 1
                                email['downloaded_attachments'] = downloaded_attachments
                        filtered_emails.append(email)

                        # Write to CSV
                        writer.writerow({
                            'From': from_email,
                            'To': to_email,
                            'Subject': subject,
                            'Date': date,
                            'no_of_attachments': no_of_attachments,
                            'no_of_attachments_downloaded': no_of_attachments_downloaded
                        })
            
            return jsonify(filtered_emails)
        else:
            return jsonify(response.json())
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(ssl_context='adhoc', port='5005')
