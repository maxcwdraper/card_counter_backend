from datetime import datetime, timedelta, timezone
from typing import Annotated
from decouple import config

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from sqlmodel import Session, select


from database import get_db
from models import Deck, User
from schemas import CreateUserRequest, Token, TokenData, UpdateUserRequest

SECRET_KEY = config("SECRET_KEY")

ALGORITHM = config("ALGORITHM")

ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

app = FastAPI(title="Card Counter")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str, db: Session) -> User | None:
    user: User | None = db.exec(select(User).where(User.token == token)).one_or_none()
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user: User | None = db.get(User, token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive User")
    return current_user

def authenticate_user(username: str, password: str, db: Session = Depends(get_db)) -> User | bool:
    user: User | None = db.get(User, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

### GET ###

@app.get("/users")
async def get_users(db: Session = Depends(get_db)) -> list[User]:
    return db.exec(select(User)).all()

@app.get("/decks")
async def get_decks(db: Session = Depends(get_db)) -> list[Deck]:
    return db.exec(select(Deck)).all()

@app.get("/users/me")
async def get_users_me(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    return current_user

### POST ###

@app.post("/token", status_code=status.HTTP_201_CREATED)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)) -> Token:
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"},)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token)

@app.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(new_user: CreateUserRequest, db: Session = Depends(get_db)) -> None:
    hashed_password: str = hash_password(new_user.password)
    user: User = User(**new_user.model_dump(), hashed_password=hashed_password)
    db.add(user)
    db.commit()

@app.post("/users/me/decks", status_code=status.HTTP_201_CREATED)
async def add_deck_to_user(deck_id: str, current_user: Annotated[User, Depends(get_current_active_user)], db: Session = Depends(get_db)) -> None:
    if deck_id in current_user.decks:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"User already has deck with ID {deck_id} in their decks.")
    new_deck: Deck = Deck(deck_id=deck_id, username=current_user.username, user=current_user)
    current_user.decks.append(new_deck)
    db.commit()

### PATCH ###

@app.patch("/users/me", status_code=status.HTTP_204_NO_CONTENT)
async def update_current_user(current_user: Annotated[User, Depends(get_current_active_user)], update_user_request: UpdateUserRequest, db: Session = Depends(get_db)) -> None:
    for field, value in update_user_request.model_dump(exclude_unset=True).items():
        setattr(current_user, field, value)
    db.commit()

### DELETE ###

@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(current_user: Annotated[User, Depends(get_current_active_user)], db: Session = Depends(get_db)) -> None:
    db.delete(current_user)
    db.commit()

@app.delete("/users/me/{deck_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_deck(deck_id: str, current_user: Annotated[User, Depends(get_current_active_user)], db: Session = Depends(get_db)) -> None:
    db.delete(current_user.decks[deck_id])
    db.commit()