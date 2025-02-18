from mitmproxy import http
import datetime
import logging
import requests
import jwt

refresh_url = 'https://your.app.com/login'


def refresh_session() -> str:
    response_json = requests.post(
        refresh_url,
        json={
            'username': 'test',
            'password': 'test'
        },
        verify=False
    ).json()

    access_token = response_json['access_token']

    logging.warning(f'Got new access token: {access_token}...')
    return access_token


def is_session_valid(access_token: str) -> bool:
    parsed_access_token = jwt.decode(access_token, options={'verify_signature': False})
    now = int(datetime.datetime.now().timestamp())
    # return true if 'exp' timestamp is still in the future
    return now < parsed_access_token['exp']


logger = logging.getLogger(__name__)
access_token = refresh_session()

def request(flow: http.HTTPFlow) -> None:
    global access_token
    if not is_session_valid(access_token):
        access_token = refresh_session()
    flow.request.headers['Authorization'] = f'Bearer {access_token}'
