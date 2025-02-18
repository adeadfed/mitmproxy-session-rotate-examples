from mitmproxy import http
import datetime
import logging
import requests
import jwt

login_url = 'https://your.app.com/login'
refresh_url = 'https://your.app.com/token/rotate'


def login() -> tuple[str,str]:
    response_json = requests.post(
        login_url,
        json={
            'username': 'test',
            'password': 'test'
        },
        verify=False
    ).json()
    access_token = response_json['access_token']
    refresh_token = response_json['refresh_token']
    logging.warning(f'Got new access access token: {access_token}...')
    logging.warning(f'Got new access refresh token: {refresh_token}...')
    return refresh_token, access_token


def refresh_session(refresh_token: str) -> tuple[str,str]:
    response_json = requests.post(
        refresh_url,
        json={
            'refresh_token': refresh_token
        }
    )
    access_token = response_json['access_token']
    refresh_token = response_json['refresh_token']
    logging.warning(f'Got new access access token: {access_token}...')
    logging.warning(f'Got new access refresh token: {refresh_token}...')
    return refresh_token, access_token


def is_session_valid(access_token: str) -> bool:
    parsed_access_token = jwt.decode(access_token, options={'verify_signature': False})
    now = int(datetime.datetime.now().timestamp())
    # return true if 'exp' timestamp is still in the future
    return now < parsed_access_token['exp']


logger = logging.getLogger(__name__)
refresh_token, access_token = refresh_session()

def request(flow: http.HTTPFlow) -> None:
    global refresh_token, access_token
    if not is_session_valid(access_token):
        refresh_token, access_token = refresh_session(refresh_token)
    flow.request.headers['Authorization'] = f'Bearer {access_token}'
