from enum import unique
from flask import Flask
from flask_restful import Api, request
from sqlalchemy import create_engine, Column, Integer, String, inspect
from sqlalchemy.orm import sessionmaker
from passlib.hash import sha256_crypt
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from flask_cors import CORS
import jwt
import datetime
import requests

app = Flask(__name__)
api = Api(app)
CORS(app)
SECRET_KEY = "yashsecret"

dbEngine = create_engine("sqlite:///data.db")
Session = sessionmaker(bind=dbEngine)

# ENCODING THE AUTHORIZATION TOKEN
def encode_auth_token(user_id):
    payload = {
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=3),
        "iat": datetime.datetime.utcnow(),
        "sub": user_id,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# DECODING THE AUTHORIZATION TOKEN
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


class UrlData(Base):
    __tablename__ = "urldata"
    id = Column(Integer, unique=True, primary_key=True)
    username = Column(String(200), nullable=False)
    shorturl = Column(String(400))
    originalurl = Column(String(700))
    date = Column(String(100))
    # __tableargs__  =
    unique = username, originalurl


@app.get("/")
def sayhello():
    return {"message": "HEllo", "user": "yash"}


# REGISTER NEW USER
@app.post("/new-user")
def register():
    args = request.json
    username = args.get("username")
    password = args.get("password")

    if username is None or password is None:
        return {"success": False, "message": "Missing required params"}, 400
    hashed_pass = sha256_crypt.encrypt(password)
    db = Session()

    user = db.query(User).filter_by(username=username).first()
    if user:
        return {"success": False, "message": "User already exists."}, 409

    new_user = User(username=username, password=hashed_pass)

    db.add(new_user)
    db.commit()
    db.close()

    return {"success": True, "message": "Successfully registerd!"}


# LOGIN USER
@app.post("/login")
def login():
    args = request.json
    username = args.get("username")
    password = args.get("password")

    db = Session()
    user = db.query(User).filter_by(username=username).first()
    if not user:
        return {"success": False, "message": "User does not exist."}

    verify_password = sha256_crypt.verify(password, user.password)

    if not verify_password:
        return {"success": False, "message": "Wrong password."}

    bearer_token = encode_auth_token(user.username)
    # print(bearer_token)
    db.close()
    return {"success": True, "bearer_token": bearer_token}


# GET THE Authorization PROCESS DONE
@app.post("/user-info")
def user_info():
    print(request.headers)
    token = request.headers.get("Authorization")
    print(token)
    # return {"succes": False}
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


# MAKE THE URL SHORT WITH API
@app.post("/shorten-url")
def get_data():

    # AUTHENTICATE USER
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
    logged_in_user = data
    logged_in = logged_in_user["username"]
    print("logged in", logged_in)
    # db.close()

    # API CALL
    url = request.args.get("url")
    print(url)
    # url_verify_1 = list()
    exists = db.query(
        db.query(UrlData).filter_by(originalurl=url, username=logged_in).exists()
    ).scalar()
    print(exists)
    if exists is True:
        return {"message": "User already searched for this URL."}

    url = "https://api.shrtco.de/v2/shorten?url={}".format(url)
    url_api = requests.get(url)
    formatted_data = url_api.json()
    print(formatted_data)
    result_ = formatted_data["result"]
    current_time = datetime.datetime.now()
    print(result_)

    # MAKE A ENTRY TO UPDATE TO DATABASE
    db = Session()
    new_entry = UrlData(
        originalurl=result_["original_link"],
        shorturl=result_["short_link"],
        date=current_time,
        username=logged_in,
    )

    db.add(new_entry)
    db.commit()
    db.close()

    return {
        "short_link": result_["short_link"],
        "user": logged_in,
        "message": "Link Created Successfully",
    }


@app.post("/entries")
def get_entries():

    # AUTHENTICATE USER
    print(request.headers)
    token = request.headers.get("Authorization")
    print(token)
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
    logged_in_user = data
    logged_in = logged_in_user["username"]

    # USER LOGGED IN

    response = list()
    url_data = db.query(UrlData).filter_by(username=logged_in).all()
    for row in url_data:
        data = row._asdict()
        del data["username"]
        del data["date"]
        del data["id"]
        response.append(data)

    return response


if __name__ == "__main__":
    Base.metadata.create_all(dbEngine)
    app.run(debug=True)
