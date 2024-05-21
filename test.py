from flask import Flask, redirect, session, url_for, request
from flask.json import jsonify
import requests
import secrets
import hashlib
import base64

app = Flask(__name__)
app.secret_key = 'secret_value' 

@app.route('/')
def homepage():
    return redirect(url_for('login'))

@app.route('/loginss')
def login():
    code_verifier = secrets.token_urlsafe(64)
    session['code_verifier'] = code_verifier
    code_challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode()
    
    callback = url_for('authorized', _external=True, _scheme='https')
    authorization_url = ('https://login.microsoftonline.com/b1e9c207-e901-43b7-a133-9d42b486216d/oauth2/v2.0/authorize'
                         '?client_id={CLIENT_ID}&response_type=code&redirect_uri={CALLBACK_URL}'
                         '&response_mode=query&scope=openid+offline_access+User.Read+Mail.Read'
                         '&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256'.format(
                             CLIENT_ID='28f8f911-d754-4a2b-a38b-b5c5576c921e',
                             CALLBACK_URL=callback,
                             CODE_CHALLENGE=code_challenge))
    return redirect(authorization_url)

@app.route('/loginss/authorized')
def authorized():
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')
    callback = url_for('authorized', _external=True, _scheme='https')

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    data = {
      'grant_type': 'authorization_code',
      'client_id': '28f8f911-d754-4a2b-a38b-b5c5576c921e',
      'client_secret': 'bxl8Q~XFhonmBAUJ_1cmSfm0bfKDWarv.OndRbjp',
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
        headers = {
            'Authorization': 'Bearer ' + session['access_token'],
        }

        response = requests.get('https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages', headers=headers)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify(response.json())
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(ssl_context='adhoc',port='5005')
