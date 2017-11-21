# -*- coding: utf-8 -*-

import logging
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

import os
import flask
import requests
import json

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from apiclient.discovery import build
from datetime import datetime
import boto3
import base64

## Aaron's code below
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('tokens')
sqs = boto3.resource('sqs')
sub_queue = sqs.Queue('https://sqs.us-west-2.amazonaws.com/985724320380/subscription_email') 
draft_queue = sqs.Queue('https://sqs.us-west-2.amazonaws.com/985724320380/subscription_email_drafts')


def save_creds(credentials):
  logging.error("1")
  c = google.oauth2.credentials.Credentials(**credentials)
  logging.error("2")
  service = build('gmail', 'v1',credentials=c)  
  logging.error("3")
  credentials['timestamp'] = str(datetime.now()).replace(" ","+") 
  logging.error("5")
  email_address = service.users().getProfile(userId='me').execute()['emailAddress'] 
  credentials['key'] = email_address

  ## If there is no new refresh token, and these credentials are already in there with a previous refresh token, then use the existing refresh token
  try:
    logging.error(credentials['refresh_token'])
    logging.error(type(credentials['refresh_token']))
    if credentials['refresh_token'] is None:
      credentials['refresh_token'] = table.get_item(Key={'key':email_address})['Item']['refresh_token']
  except:
    logging.error("get existing refresh_token failed - sending None")
    credentials['refresh_token'] = None
  logging.error("6")
  table.put_item(Item=credentials)
  logging.error("7")
  del credentials['timestamp']
  del credentials['key']
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

@application.route('/inbox',methods=['POST'])
def inbox_message():
  logging.error("Got something inboxy!")
  json_data = flask.request.data
  data = json.loads(json_data)
  if 'message' in data:
    if 'data' in data['message']:
      logging.error(base64.b64decode(data['message']['data']))
    else:
      logging.error(json_data)
  else:
    logging.error(json_data)
  sub_queue.send_message( MessageBody=flask.request.data)
  logging.error(json.dumps(flask.request.data))
  return flask.redirect("https://sendvibe.email"), 200

@application.route('/sub',methods=['POST'])
def sub_message():
  logging.error("Got something normal!")
  json_data = flask.request.data
  data = json.loads(json_data)
  if 'message' in data:
    if 'data' in data['message']:
      logging.error(base64.b64decode(data['message']['data']))
    else:
      logging.error(json_data)
  else:
    logging.error(json_data)
  sub_queue.send_message( MessageBody=flask.request.data)
  return flask.redirect("https://sendvibe.email"), 200

@application.route('/drafts',methods=['POST'])
def draft_message():
  logging.error("Got something drafty!")
  json_data = flask.request.data
  data = json.loads(json_data)
  if 'message' in data:
    if 'data' in data['message']:
      logging.error(base64.b64decode(data['message']['data']))
    else:
      logging.error(json_data)
  else:
    logging.error(json_data)
  draft_queue.send_message( MessageBody=json_data)
  return flask.redirect("https://sendvibe.email"), 200

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
  ##TODO: Needs error handling if user clicks cancel
  ##server sends back 'access_denied'

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

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  application.run('localhost', 5000, debug=True)
