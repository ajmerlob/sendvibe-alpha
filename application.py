# -*- coding: utf-8 -*-

import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from datetime import datetime

## Aaron's code below
try:
  import cPickle as pickle
except:
  import pickle

def save_creds(credentials):
  filename = str(datetime.now()).replace(" ","+")
  database_file = './saved_tokens/' + filename + ".token"
  pickle.dump(credentials, open(database_file,'wb'))
## End Aaron's code

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"
  
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'

# This OAuth 2.0 access scope allows for read access to the
# authenticated user's gmail account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

application = flask.Flask(__name__)
# See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
application.secret_key = 'youdontknowmelikeiknowme123123231homie'

## Turfs user to consumer site
@application.route('/')
def index():
  return flask.redirect("https://sendvibe.email")

## Authorize and oauth2callback work as a 1-2 punch to grab 
## the all important token.  This routes the user to the 
## 3rd party site for authentication
@application.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = flask.url_for('oauth2callback', _external=True, _scheme='https')

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)

## This gets a callback from the 3rd party site and
## then trades what it gets for a cool token
@application.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True, _scheme='https')

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)
  # Aaron's note: this is what I'm doing with the token
  save_creds(flask.session['credentials'])
  # End Aaron section

  return flask.redirect('https://sendvibe.email/thanks-for-signing-up')

# If the user is currently authenticated, this can revoke
# the permissions, so the app no longer has access
# If there isn't a pre-existing session with the user's
# data in there, you'd have to authenticate before a
# revoke could happen, but since that would probably seem
# shady to the user, I just tell them where they can find
# the 3rd party revoke.
@application.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return(flask.redirect("https://sendvibe.email/this-is-awkward"))

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return(flask.redirect("https://sendvibe.email/sorry-to-see-you-go"))
  else:
    return(flask.redirect("https://sendvibe.email/this-is-awkward"))

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

### For use in testing with currently authenticated user
#@application.route('/test')
#def test_api_request():
#  if 'credentials' not in flask.session:
#    return flask.redirect('authorize')
#
#  # Load credentials from the session.
#  credentials = google.oauth2.credentials.Credentials(
#      **flask.session['credentials'])
#
#  gmail = googleapiclient.discovery.build(
#      API_SERVICE_NAME, API_VERSION, credentials=credentials)
#
#  results = gmail.users().messages().list(userId='me').execute()
#
#  # Save credentials back to session in case access token was refreshed.
#  # ACTION ITEM: In a production app, you likely want to save these
#  #              credentials in a persistent database instead.
#  flask.session['credentials'] = credentials_to_dict(credentials)
#  save_creds(flask.session['credentials'])
#
#  return flask.jsonify(**results)

## This clears out the authenticated user from the session
## Can be used in testing the revoke error condition.
#@application.route('/clear')
#def clear_credentials():
#  if 'credentials' in flask.session:
#    del flask.session['credentials']
#  return ('Credentials have been cleared.<br><br>' +
#          print_index_table())


#def print_index_table():
#  return ('<table>' +
#          '<tr><td><a href="/test">Test an API request</a></td>' +
#          '<td>Submit an API request and see a formatted JSON response. ' +
#          '    Go through the authorization flow if there are no stored ' +
#          '    credentials for the user.</td></tr>' +
#          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
#          '<td>Go directly to the authorization flow. If there are stored ' +
#          '    credentials, you still might not be prompted to reauthorize ' +
#          '    the application.</td></tr>' +
#          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
#          '<td>Revoke the access token associated with the current user ' +
#          '    session. After revoking credentials, if you go to the test ' +
#          '    page, you should see an <code>invalid_grant</code> error.' +
#          '</td></tr>' +
#          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
#          '<td>Clear the access token currently stored in the user session. ' +
#          '    After clearing the token, if you <a href="/test">test the ' +
#          '    API request</a> again, you should go back to the auth flow.' +
#          '</td></tr></table>')


if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  application.run('localhost', 5000, debug=True)
