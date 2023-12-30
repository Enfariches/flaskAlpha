from app.config.db import db
from app.models.user import Users, Profiles, TokenBlocklist
from app.parsers.parsers import registerParser, loginParser, profileParser
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_current_user, get_jwt
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash


class Register(Resource):
    def post(self):
        try:
            user = registerParser.parse_args()
            user_in_base = Users.query.filter_by(login=user["login"]).first()
            if user_in_base:
                return {'msg': 'User {} already exists'.format(user['login'])}
            else:
                user["password"] = generate_password_hash(user["password"])
                new_user = Users(login=user["login"], hash_password=user["password"],
                                 email=user["email"], role=user["role"])
                db.session.add(new_user)
                db.session.commit()
                return {'msg': "user was created"}, 201
        except Exception as e:
            return {"msg": "Something went wrong"}, 500


class GetUsers(Resource):
    @jwt_required()
    def get(self, user_id=None):
        try:
            if user_id is None:
                users_lst = Users.query.all()
            else:
                users_lst = Users.query.filter_by(id=user_id).all()
            if users_lst:
                users_slv = {}
                for user in users_lst:
                    users_slv[user.id] = {"login": user.login, "password": user.hash_password,
                                          "email": user.email, "role": user.role}
                return users_slv, 200
            else:
                return {"msg": "user is not found"}
        except Exception as e:
            print(e)


class Login(Resource):
    def post(self):
        try:
            user = loginParser.parse_args()
            user_in_base = Users.query.filter_by(login=user["login"]).first()
            if user_in_base:
                if check_password_hash(user_in_base.hash_password, user["password"]):
                    token = create_access_token(identity=user['login'])
                    return {"msg": "successful authorization",
                            "user": user_in_base.login,
                            "role": user_in_base.role,
                            'token': token
                            }, 200
                else:
                    return {"msg": "password is not correct"}, 400
            return {"msg": "user is not found"}, 404
        except Exception as e:
            return {"msg": "login error"}, 500
    @jwt_required()
    def get(self):
        return {"msg": "you are logged in"}


class Profile(Resource):
    @jwt_required()
    def post(self):
        try:
            profile = profileParser.parse_args()
            user = Users.query.filter_by(login=get_current_user()).first()
            profile_in_base = Profiles.query.filter_by(user_id=user.id).first()
            username_in_base = Profiles.query.filter_by(username=profile.username).first()
            if profile_in_base or username_in_base:
                return {"msg": "this user or username already exists"}, 201
            else:
                new_profile = Profiles(username=profile["username"], description=profile.get("description"),
                                       avatar_url=profile.get("avatar_url"),
                                       user_id=user.id)
                db.session.add(new_profile)
                db.session.commit()
                return {"msg": "success"}, 200
        except Exception as e:
            return {"msg": "create profile error"}, 500

    @jwt_required()
    def put(self):
        try:
            profile_args = profileParser.parse_args()
            user = Users.query.filter_by(login=get_current_user()).first()
            profile = Profiles.query.filter_by(user_id=user.id).first()
            if profile:
                if profile_args["username"] is None:
                    profile.avatar_url = profile_args["avatar_url"]
                elif profile_args["avatar_url"] is None:
                    profile.username = profile_args["username"]
                else:
                    profile.username = profile_args["username"]
                    profile.avatar_url = profile_args["avatar_url"]
            db.session.commit()
            return {"msg": "success change"}, 2001
        except Exception as e:
            return {"msg": f"refresh profile info error {e}"}, 500

    @jwt_required()
    def get(self):
        try:
            user = Users.query.filter_by(login=get_current_user()).first()
            profile = Profiles.query.filter_by(user_id=user.id).first()
            if profile:
                profile_slv = {"username": profile.username, "description": profile.description,
                               "avatar_url": profile.avatar_url,
                               "balance": profile.balance,
                               "completed_surveys": profile.complete_survey}
                return profile_slv, 200
            else:
                return {"msg": "not profile"}, 201
        except Exception as e:
            return {"msg": "get profile error"}, 500


class Logout(Resource):
    @jwt_required()
    def delete(self):
        try:
            jti = get_jwt()["jti"]
            db.session.add(TokenBlocklist(jti=jti))
            db.session.commit()
            return {"msg": "logout success"}, 200
        except Exception as e:
            return {"msg": "logout error"}, 500
