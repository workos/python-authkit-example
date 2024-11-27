from dotenv import load_dotenv
import os
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, make_response
from workos import WorkOSClient

load_dotenv()

app = Flask(__name__)

workos = WorkOSClient(
    api_key=os.getenv("WORKOS_API_KEY"), client_id=os.getenv("WORKOS_CLIENT_ID")
)

cookie_password = os.getenv("WORKOS_COOKIE_PASSWORD")


# Decorator to check if the user is authenticated. If not, redirect to login
def with_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session = workos.user_management.load_sealed_session(
            sealed_session=request.cookies.get("wos_session"),
            cookie_password=cookie_password,
        )
        auth_response = session.authenticate()
        if auth_response.authenticated:
            return f(*args, **kwargs)

        if (
            auth_response.authenticated == False
            and auth_response.reason == "no_session_cookie_provided"
        ):
            return make_response(redirect("/login"))

        # If no session, attempt a refresh
        try:
            print("Refreshing session")
            result = session.refresh()
            if result.authenticated == False:
                return make_response(redirect("/login"))

            response = make_response(redirect(request.url))
            response.set_cookie(
                "wos_session",
                result.sealed_session,
                secure=True,
                httponly=True,
                samesite="lax",
            )
            return response
        except Exception as e:
            print("Error refreshing session", e)
            response = make_response(redirect("/login"))
            response.delete_cookie("wos_session")
            return response

    return decorated_function


@app.route("/")
def home():

    session = workos.user_management.load_sealed_session(
        sealed_session=request.cookies.get("wos_session"),
        cookie_password=cookie_password,
    )
    response = session.authenticate()

    current_user = response.user if response.authenticated else None

    return render_template("index.html", current_user=current_user)


@app.route("/account")
@with_auth
def account():
    session = workos.user_management.load_sealed_session(
        sealed_session=request.cookies.get("wos_session"),
        cookie_password=cookie_password,
    )
    response = session.authenticate()

    current_user = response.user if response.authenticated else None

    return render_template("account.html", current_user=current_user)


@app.route("/callback")
def callback():
    code = request.args.get("code")

    try:
        auth_response = workos.user_management.authenticate_with_code(
            code=code,
            session={"seal_session": True, "cookie_password": cookie_password},
        )

        print("Successfully authenticated")

        # store the session in a cookie
        response = make_response(redirect("/"))
        response.set_cookie(
            "wos_session",
            auth_response.sealed_session,
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    except Exception as e:
        print("Error authenticating with code", e)
        return redirect(url_for("/login"))


@app.route("/login")
def login():
    authorization_url = workos.user_management.get_authorization_url(
        provider="authkit", redirect_uri=os.getenv("WORKOS_REDIRECT_URI")
    )

    return redirect(authorization_url)


@app.route("/logout")
def logout():
    session = workos.user_management.load_sealed_session(
        sealed_session=request.cookies.get("wos_session"),
        cookie_password=cookie_password,
    )
    url = session.get_logout_url()

    # After log out has succeeded, the user will be redirected to your app homepage which is configured in the WorkOS dashboard
    response = make_response(redirect(url))
    response.delete_cookie("wos_session")

    return response


if __name__ == "__main__":
    app.run(debug=True, port=3000)
