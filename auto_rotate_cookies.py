from mitmproxy import http
import datetime
import logging
import requests

refresh_url = 'https://your.app.com/login'


def refresh_session() -> str:
    response = requests.post(
        refresh_url,
        json={
            'username': 'test',
            'password': 'test'
        },
        verify=False
    )
    cookies = response.cookies.get_dict()
    logging.warning(f'Got new cookies: {cookies}...')
    return cookies


def is_session_valid(response: http.Response) -> bool:
    return response.status_code != 401


logger = logging.getLogger(__name__)
cookies = refresh_session()

def response(flow: http.HTTPFlow) -> None:
    global cookies
    if not is_session_valid(flow.response):
        cookies = refresh_session()


def request(flow: http.HTTPFlow) -> None:
    global cookies
    flow.request.cookies.update(cookies)
