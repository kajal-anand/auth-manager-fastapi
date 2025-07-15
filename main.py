# fastapi_auth_project/main.py

from fastapi import FastAPI, Depends, HTTPException, Request, status, Response, Cookie, Header
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import logging
import traceback

# === Logging Setup ===
logging.basicConfig(filename="auth.log",
                    level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# === Configs ===
SECRET_KEY = "welcome"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === DB Setup ===
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# === Password Hashing ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# === JWT ===

class TokenData(BaseModel):
    username: str | None = None

# === User Model ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


Base.metadata.create_all(bind=engine)

# === Utils ===
def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === Auth Decorators ===
def is_logged_in_cookie(request: Request, token: str = Cookie(None)):
    try:
        if not token:
            raise HTTPException(status_code=403, detail="Not authenticated")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Invalid credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=403, detail="Token verification failed")

def is_logged_in_bearer(authorization: str = Header(...)):
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=403, detail="Invalid auth header")
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Invalid credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=403, detail="Bearer token verification failed")

# === FastAPI App ===
app = FastAPI()

# === Routes ===

@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {traceback.format_exc()}")
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

# Public route
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <h1>Welcome</h1>
    <a href="/login-page">Login (Cookie)</a> | <a href="/register-page">Register</a> | <a href="/token-login-page">Login (Token)</a>
    """

# Public route
@app.get("/about")
async def about():
    return {"message": "This is a public about page."}

# Registration
@app.get("/register-page", response_class=HTMLResponse)
async def register_page():
    return """
    <form action="/register" method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit">
    </form>
    """

@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username, password = form['username'], form['password']
    user = db.query(User).filter_by(username=username).first()
    if user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    return RedirectResponse("/login-page", status_code=302)

# Login with cookie
@app.get("/login-page", response_class=HTMLResponse)
async def login_page():
    return """
    <form action="/login" method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit">
    </form>
    """

@app.post("/login")
async def login(request: Request, response: Response, db: Session = Depends(get_db)):
    form = await request.form()
    username, password = form['username'], form['password']
    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid login")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    response = RedirectResponse("/dashboard", status_code=302)
    response.set_cookie(key="token", value=access_token, httponly=True)
    return response

# Login with bearer token (API)
@app.post("/api/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Token login page using JS + LocalStorage
@app.get("/token-login-page", response_class=HTMLResponse)
async def token_login_page():
    return """
    <h3>Login Using Bearer Token</h3>
    <form onsubmit="login(event)">
        Username: <input id="username"><br>
        Password: <input id="password" type="password"><br>
        <button type="submit">Login</button>
    </form>
    <script>
        async function login(event) {
            event.preventDefault();
            const res = await fetch('/api/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `username=${username.value}&password=${password.value}`
            });
            const data = await res.json();
            localStorage.setItem('access_token', data.access_token);
            window.location = '/token-dashboard';
        }
    </script>
    """



# Protected route with cookie
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(username: str = Depends(is_logged_in_cookie)):
    return f"<h2>Welcome {username} (Cookie Auth)!</h2><a href='/logout'>Logout</a>"

# Protected route with token
@app.get("/token-dashboard", response_class=HTMLResponse)
async def token_dashboard():
    return """
    <script>
        async function load() {
            const token = localStorage.getItem('access_token');
            const res = await fetch('/profile', { headers: { Authorization: `Bearer ${token}` } });
            const data = await res.json();
            document.body.innerHTML += `<p>${data.message}</p>`;
        }
        load();
    </script>
    <h3>Bearer Token Dashboard</h3>
    """

# Protected profile route (works with bearer token)
@app.get("/profile")
async def profile(username: str = Depends(is_logged_in_bearer)):
    return {"message": f"Hello {username}, this is your profile via token."}

# Logout
@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("token")
    return response
