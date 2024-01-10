from app.config.config import postgresqlConfig
from app.config.db import db
from app.models.user import TokenBlocklist, Users
from app.resources.surveys import CreateSurvey, SendAnswers, CompleteSurvey, GetSurveys, GetAnswers, MySurveys
from app.resources.user import Register, GetUsers, Login, Profile, Logout
from flask import Flask
from datetime import timedelta
from flask_restful import Api
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = postgresqlConfig
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'

jwt = JWTManager(app)
api = Api(app)

with app.app_context():
    db.init_app(app)
    db.create_all()


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None


@jwt.user_lookup_loader
def user_lookup_callback(jwt_header, jwt_data):
    sub = jwt_data['sub']
    id = sub['id'] if type(sub) is dict else sub
    return Users.get_by_id(id)


api.add_resource(Register, "/api/register/", "/api/b/register/")
api.add_resource(GetUsers, "/api/users/", "/api/users/<int:user_id>/")
api.add_resource(Login, "/api/login/", "/api/b/login/")
api.add_resource(Profile, "/api/profile/")
api.add_resource(Logout, "/api/logout/")
api.add_resource(CreateSurvey, "/api/createsurvey/")
api.add_resource(SendAnswers, "/api/completesurvey/<int:survey_id>/sendanswers/")
api.add_resource(CompleteSurvey, "/api/completesurvey/<int:survey_id>/")
api.add_resource(GetSurveys, "/api/surveys/", "/api/surveys/<int:survey_id>/")
api.add_resource(GetAnswers, "/api/getanswers/<int:survey_id>/")
api.add_resource(MySurveys, "/api/mysurveys/")
