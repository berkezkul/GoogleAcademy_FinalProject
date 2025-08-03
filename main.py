from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr

class RegisterForm(BaseModel):
    email: EmailStr
    password: str


app = FastAPI()


templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret for JWT
SECRET_KEY = "4226493118f87828fc02314f3c9bd1622337f5c2d8887d356200cfa21ba2dadd"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# mock database
fake_users_db = {
    "test@example.com": {
        "email": "test@example.com",
        "hashed_password": pwd_context.hash("123456"),
    }
}

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def authenticate_user(email: str, password: str):
    user = fake_users_db.get(email)
    if not user:
        return None
    if not pwd_context.verify(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.get("/", response_class=HTMLResponse)
def show_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/home", response_class=HTMLResponse)
def show_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    #token = create_access_token({"sub": user["email"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    response = RedirectResponse(url="/home", status_code=303)
    return response


@app.post("/register")
def register_user(user: RegisterForm):
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists.")

    hashed_password = pwd_context.hash(user.password)
    fake_users_db[user.email] = {
        "email": user.email,
        "hashed_password": hashed_password,
    }
    return RedirectResponse(url="/login", status_code=303)


