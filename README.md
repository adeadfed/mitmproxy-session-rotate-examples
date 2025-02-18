# mitmproxy session rotation examples
Some example mitmproxy scripts from my recent blogpost on adeadfed.com that you can use to automate session rotation.

1. `auto_rotate_cookies.py` - automated rotation of cookie-based sessions
2. `auto_rotate_jwt_simple.py` - automated rotation of JWT sessions that only use access tokens
3. `auto_rotate_jwt_refresh_token.py` - automated rotation of JWT sessions with refresh tokens

# Usage
1. Clone this repo and install prerequisites
```
git clone https://github.com/adeadfed/mitmproxy-session-rotate-examples
cd mitmproxy-session-rotate-examples
pip install -r requirements.txt
```
2. Choose the script that you need, edit the login sequence code
3. Run it with mitmproxy
```
mitmproxy -s auto_rotate_jwt_simple.py --listen-host localhost --listen-port 8081 -k
```
4. Setup your software to run through the mitmproxy at http://localhost:8081
