from dotenv import load_dotenv
import os

from flask import Flask, request, render_template, redirect, url_for, make_response
from workos import WorkOSClient

load_dotenv()

app = Flask(__name__)

workos = WorkOSClient(api_key=os.getenv('WORKOS_API_KEY'), client_id=os.getenv('WORKOS_CLIENT_ID'))

cookie_password = os.getenv('WORKOS_COOKIE_PASSWORD')

@app.route('/')
def home():

    session = workos.user_management.load_sealed_session(session_data=request.cookies.get('wos_session'), cookie_password=cookie_password)
    response = session.authenticate()

    print(response)

    current_user = response.user if response.authenticated else None
    print(current_user)
    return render_template('index.html', current_user=current_user)

@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/callback')
def callback():
    code = request.args.get('code')

    try:
        auth_response = workos.user_management.authenticate_with_code(code=code, session={ "seal_session": True, "cookie_password": cookie_password })

        # store the session in a cookie
        response = make_response(redirect('/'))
        response.set_cookie('wos_session', auth_response.sealed_session, secure=True, httponly=True, samesite='lax')
        return response

    except Exception as e:
        print(e)
        return redirect(url_for('/login'))

@app.route('/login')
def login():
    authorization_url = workos.user_management.get_authorization_url(provider="authkit", redirect_uri=os.getenv('WORKOS_REDIRECT_URI'))

    return redirect(authorization_url)

@app.route('/logout')
def logout(request, response):
    session = workos.user_management.load_sealed_session(session_data=request.cookies.get('wos_session'), cookie_password=cookie_password)
    url = session.get_logout_url()
    response.delete_cookie('wos_session')

    # After log out has succeeded, the user will be redirected to your app homepage which is configured in the WorkOS dashboard
    return redirect(url)

if __name__ == '__main__':
    app.run(debug=True)
