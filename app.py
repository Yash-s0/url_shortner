from enum import unique
from flask import Flask
from flask_restful import Api, request
from sqlalchemy import create_engine, Column, Integer, String, inspect, Table, MetaData
from sqlalchemy.orm import sessionmaker
from passlib.hash import sha256_crypt
from sqlalchemy.ext.declarative import as_declarative, declared_attr
import jwt
import datetime
import requests


app = Flask(__name__)
api = Api(app)
meta = MetaData()
SECRET_KEY = "yashsecret"

dbEngine = create_engine("sqlite:///data.db")
Session = sessionmaker(bind=dbEngine)


def encode_auth_token(user_id):
    payload = {
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5),
        "iat": datetime.datetime.utcnow(),
        "sub": user_id,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=["HS256"])
        return {"success": True, "username": payload["sub"]}
    except jwt.ExpiredSignatureError:
        return {"success": False, "message": "Signature expired. Please log in again."}
    except jwt.InvalidTokenError:
        return {"success": False, "message": "Signature expired. Please log in again."}


@as_declarative()
class Base:
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()

    def _asdict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, unique=True, primary_key=True)
    username = Column(String(200), unique=True, nullable=False)
    password = Column(String(200), unique=False, nullable=False)

    # __tablename__ = "urldata"
    # id = Column(Integer, unique=True, primary_key=True)
    # username = Column(String(200), unique=True, nullable=False)
    # shorturl = Column(String(400), unique=True, nullable=False)
    # originalurl = Column(String(700), unique=True, nullable=False)
    # date = Column(String(100), unique=True, nullable=False)


@app.get("/new-user")
def register():
    args = request.json
    username = args.get("username")
    password = args.get("password")
    hashed_pass = sha256_crypt.encrypt(password)

    if username is None or password is None:
        return {"success": False, "message": "Missing required params"}, 400
    db = Session()

    user = db.query(User).filter_by(username=username).first()
    if user:
        return {"success": False, "message": "User already exists."}, 409

    new_user = User(username=username, password=hashed_pass)

    db.add(new_user)
    db.commit()
    db.close()

    return {"success": True, "message": "Successfull register!"}


@app.post("/login")
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    db = Session()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        return {"success": False, "message": "User does not exist."}

    verify_password = sha256_crypt.verify(password, user.password)

    if not verify_password:
        return {"success": False, "message": "Wrong password."}

    bearer_token = encode_auth_token(user.username)
    print(bearer_token)
    db.close()
    return {"succes": True, "bearer_token": bearer_token}


@app.get("/user-info")
def user_info():
    token = request.headers.get("Authorization")
    if token is None:
        return {"success": False, "message": "Session expried, please login"}, 404

    bearer_token = token.split("Bearer ")[1]
    verify = decode_auth_token(bearer_token)
    if "success" in verify and verify["success"] is False:
        return verify

    db = Session()
    user = db.query(User).filter_by(username=verify["username"]).first()
    data = user._asdict()
    del data["password"]
    del data["id"]
    return data


@app.route("/shorten-url")
def get_data():
    url = request.args.get("url")
    url = "https://api.shrtco.de/v2/shorten?url={}".format(url)
    url_api = requests.get(url)
    formatted_data = url_api.json()
    result_ = formatted_data["result"]
    current_time = datetime.datetime.now()
    return {
        "success": True,
        "short_link": result_["short_link"],
        "original_link": result_["original_link"],
        "date": current_time,
    }


if __name__ == "__main__":
    Base.metadata.create_all(dbEngine)
    app.run(debug=True)
