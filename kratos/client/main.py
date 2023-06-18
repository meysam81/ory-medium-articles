import base64
import time
from http import HTTPStatus
from pathlib import Path
from pprint import pformat
from urllib.parse import urlencode, urljoin

import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from settings import settings
from utils import get_logger

HERE = Path(__file__).parent
STATIC = HERE / "static"
TEMPLATES = HERE / "templates"

logger = get_logger(__name__, settings.LOG_LEVEL)
app = FastAPI(title=settings.APP_NAME)
templates = Jinja2Templates(directory=TEMPLATES)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


REDIRECT_STATUSES = [
    HTTPStatus.SEE_OTHER,
    HTTPStatus.TEMPORARY_REDIRECT,
    HTTPStatus.PERMANENT_REDIRECT,
    HTTPStatus.FOUND,
]


class ServerSession:
    session_store: dict = {}

    @classmethod
    async def get(cls, key):
        return cls.session_store.get(key)

    @classmethod
    async def set(cls, key, value):
        cls.session_store[key] = value

    @staticmethod
    def request_identifier(request: Request) -> str:
        return f"{request.client.host}:{request.client.port}"


class Encyption:
    def __init__(self, encryption_key: str, encryption_algorithm: str):
        self.encryption_key = encryption_key
        self.encryption_algorithm = encryption_algorithm
        self.fernet = Fernet(base64.urlsafe_b64encode(encryption_key))

    async def encrypt(self, value: str):
        return self.fernet.encrypt(value.encode()).decode()

    async def decrypt(self, value: str):
        return self.fernet.decrypt(value.encode()).decode()


csrf_encryptor = Encyption(
    settings.CSRF_ENCRYPTION_KEY, settings.CSRF_ENCRYPTION_ALGORITHM
)


@app.middleware("http")
async def return_to_query_param_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    params = {}
    if return_to := request.query_params.get("return_to"):
        params["return_to"] = return_to
    if response.status_code in REDIRECT_STATUSES:
        qp = urlencode(params)
        response.headers["Location"] = f"{response.headers['Location']}?{qp}"
    return response


@app.middleware("http")
async def timing_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    if request.query_params:
        request_info = f"{request.method} {request.url}?{request.query_params}"
    else:
        request_info = f"{request.method} {request.url}"
    logger.info(f"{request_info} - {process_time:.2f}s")
    return response


@app.get(settings.ERROR_URI)
async def error(request: Request):
    logger.error(pformat(dict(request.headers)))
    logger.error(await request.body())
    return {"message": "Error"}


@app.get("/healthz")
async def health():
    return {"message": "OK"}


@app.get(
    settings.INDEX_URI,
    responses={
        HTTPStatus.OK: {
            "description": "The user is already logged in and will gets the session info"
        },
        HTTPStatus.SEE_OTHER: {
            "description": "The user is not logged in and will be redirected to the login page"
        },
    },
)
async def index(request: Request):
    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_WHOAMI_URI),
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code == HTTPStatus.OK:
        return result.json()

    return RedirectResponse(url=settings.LOGIN_URI, status_code=HTTPStatus.SEE_OTHER)


@app.get(settings.LOGIN_URI, response_class=HTMLResponse)
async def login(
    request: Request,
    flow: str = None,
):
    redirect_url = urljoin(
        settings.KRATOS_PUBLIC_URL,
        settings.KRATOS_LOGIN_BROWSER_URI,
    )

    if not flow:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    logger.info(pformat(dict(request.headers)))

    async with httpx.AsyncClient(base_url=settings.KRATOS_PUBLIC_URL) as client:
        result = await client.get(
            settings.KRATOS_LOGIN_FLOW_URI,
            params={"id": flow},
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    logger.info(pformat(dict(result.headers)))

    if result.status_code in [HTTPStatus.NOT_FOUND, HTTPStatus.GONE]:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    json_ = result.json()

    inputs = []
    csrf_token = None
    for input_ in json_["ui"]["nodes"]:
        if input_["attributes"]["name"] == "csrf_token":
            csrf_token = input_["attributes"]["value"]
            continue
        inputs.append(
            {
                "id": input_["attributes"]["name"],
                "label": input_["meta"].get("label", {}).get("text"),
                "required": input_["attributes"].get("required", False),
                "type": input_["attributes"]["type"],
                "value": input_["attributes"].get("value", ""),
            }
        )

    action = json_["ui"]["action"]
    method = json_["ui"]["method"]

    response = templates.TemplateResponse(
        "login.html",
        {
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "inputs": inputs,
            "request": request,
        },
    )
    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get(settings.VERIFICATION_URI, response_class=HTMLResponse)
async def verification(request: Request, flow: str = None, code: str = ""):
    redirect_url = (
        urljoin(
            settings.KRATOS_PUBLIC_URL,
            settings.KRATOS_VERIFICATION_BROWSER_URI,
        )
        + f"?return_to=/"
    )
    if not flow:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    logger.debug(pformat(dict(request.headers)))

    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(
                settings.KRATOS_PUBLIC_URL,
                settings.KRATOS_VERIFICATION_FLOW_URI,
            ),
            params={"id": flow},
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code in [HTTPStatus.NOT_FOUND, HTTPStatus.GONE]:
        return RedirectResponse(url=redirect_url, status_code=HTTPStatus.SEE_OTHER)

    json_ = result.json()

    if json_.get("state") == "passed_challenge":
        return RedirectResponse(url="/", status_code=HTTPStatus.SEE_OTHER)

    inputs = []
    csrf_token = None
    for input_ in json_["ui"]["nodes"]:
        if input_["attributes"]["name"] == "csrf_token":
            csrf_token = input_["attributes"]["value"]
            continue
        name = input_["attributes"]["name"]
        value = code if name == "code" else input_["attributes"].get("value", "")
        inputs.append(
            {
                "id": name,
                "label": input_["meta"].get("label", {}).get("text"),
                "required": input_["attributes"].get("required", False),
                "type": input_["attributes"]["type"],
                "value": value,
            }
        )

    action = json_["ui"]["action"]
    method = json_["ui"]["method"]

    response = templates.TemplateResponse(
        "verification.html",
        {
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "inputs": inputs,
            "request": request,
        },
    )

    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get(settings.REGISTRATION_URI, response_class=HTMLResponse)
async def registration(request: Request, flow: str = None):
    redirect_url = urljoin(
        settings.KRATOS_PUBLIC_URL, settings.KRATOS_REGISTRATION_BROWSER_URI
    )
    if not flow:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    logger.debug(pformat(dict(request.headers)))

    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_REGISTRATION_FLOW_URI),
            params={"id": flow},
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code in [HTTPStatus.NOT_FOUND, HTTPStatus.GONE]:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    json_ = result.json()
    inputs = []
    csrf_token = None
    for input_ in json_["ui"]["nodes"]:
        if input_["attributes"]["name"] == "csrf_token":
            csrf_token = input_["attributes"]["value"]
            continue
        inputs.append(
            {
                "id": input_["attributes"]["name"],
                "label": input_["meta"].get("label", {}).get("text"),
                "required": input_["attributes"].get("required", False),
                "type": input_["attributes"]["type"],
                "value": input_["attributes"].get("value"),
            }
        )

    action = json_["ui"]["action"]
    method = json_["ui"]["method"]

    response = templates.TemplateResponse(
        "registration.html",
        {
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "inputs": inputs,
            "request": request,
        },
    )

    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get(settings.LOGOUT_URI, response_class=HTMLResponse)
async def logout(request: Request):
    logger.debug(pformat(dict(request.headers)))

    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_LOGOUT_BROWSER_URI),
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code == HTTPStatus.UNAUTHORIZED:
        return RedirectResponse(url="/", status_code=HTTPStatus.SEE_OTHER)

    json_ = result.json()

    response = templates.TemplateResponse(
        "logout.html",
        {
            "request": request,
            "logout_url": json_["logout_url"],
        },
    )

    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get(settings.RECOVERY_URI, response_class=HTMLResponse)
async def recovery(request: Request, flow: str = None):
    redirect_url = urljoin(
        settings.KRATOS_PUBLIC_URL, settings.KRATOS_RECOVERY_BROWSER_URI
    )
    if not flow:
        return RedirectResponse(
            url=redirect_url + f"?return_to={settings.LOGIN_URI}",
            status_code=HTTPStatus.TEMPORARY_REDIRECT,
        )

    logger.debug(pformat(dict(request.headers)))

    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_RECOVERY_FLOW_URI),
            params={"id": flow},
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code in [HTTPStatus.NOT_FOUND, HTTPStatus.GONE]:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    json_ = result.json()
    inputs = []
    csrf_token = None
    for input_ in json_["ui"]["nodes"]:
        if input_["attributes"]["name"] == "csrf_token":
            csrf_token = input_["attributes"]["value"]
            continue
        inputs.append(
            {
                "id": input_["attributes"]["name"],
                "label": input_["meta"].get("label", {}).get("text"),
                "required": input_["attributes"].get("required", False),
                "type": input_["attributes"]["type"],
                "value": input_["attributes"].get("value", ""),
            }
        )

    action = json_["ui"]["action"]
    method = json_["ui"]["method"]

    response = templates.TemplateResponse(
        "recovery.html",
        {
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "inputs": inputs,
            "request": request,
        },
    )

    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get(settings.SETTINGS_URI, response_class=HTMLResponse, name="settings")
async def profile(request: Request, flow: str = None):
    redirect_url = (
        urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_SETTINGS_BROWSER_URI)
        + f"?return_to={settings.LOGIN_URI}"
    )

    if not flow:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    logger.debug(pformat(dict(request.headers)))

    async with httpx.AsyncClient() as client:
        result = await client.get(
            urljoin(settings.KRATOS_PUBLIC_URL, settings.KRATOS_SETTINGS_FLOW_URI),
            params={"id": flow},
            headers={"accept": "application/json"},
            cookies=request.cookies,
        )

    if result.status_code in [HTTPStatus.NOT_FOUND, HTTPStatus.GONE]:
        return RedirectResponse(
            url=redirect_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
        )

    json_ = result.json()
    inputs = []
    csrf_token = None
    for input_ in json_["ui"]["nodes"]:
        name = input_["attributes"].get("name")
        value = input_["attributes"].get("value", "")
        type_ = input_["attributes"].get("type")

        if name == "csrf_token":
            csrf_token = input_["attributes"]["value"]
            continue

        if base64_img := input_["attributes"].get("src"):
            name = input_["attributes"]["id"]
            value = base64_img
            type_ = input_["attributes"]["node_type"]

        elif input_["attributes"].get("id") == "totp_secret_key":
            name = input_["attributes"]["id"]
            type_ = input_["attributes"]["node_type"]
            value = input_["attributes"]["text"]["text"]

        elif input_["attributes"].get("id") == "lookup_secret_codes":
            name = input_["attributes"]["id"]
            type_ = input_["attributes"]["node_type"]
            value = input_["attributes"]["text"]["text"]

        inputs.append(
            {
                "id": name,
                "label": input_["meta"].get("label", {}).get("text"),
                "required": input_["attributes"].get("required", False),
                "type": type_,
                "value": value,
            }
        )

    action = json_["ui"]["action"]
    method = json_["ui"]["method"]

    response = templates.TemplateResponse(
        "settings.html",
        {
            "action": action,
            "method": method,
            "csrf_token": csrf_token,
            "inputs": inputs,
            "request": request,
        },
    )

    for cookie, value in request.cookies.items():
        response.set_cookie(cookie, value)

    return response


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(STATIC / "favicon.jpeg", media_type="image/jpeg")


if __name__ == "__main__":
    import uvicorn

    logger.info(f"Listening on {settings.HOST}:{settings.PORT}")

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        reload_dirs=[HERE],
        log_level=settings.LOG_LEVEL.lower(),
    )
