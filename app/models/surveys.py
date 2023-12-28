from datetime import datetime
from app.config.db import db
from sqlalchemy.dialects.postgresql import JSONB, ARRAY


class Surveys(db.Model):
    def __init__(self, title, description, logoPosition, value, pages, user_id):
        self.title = title
        self.description = description
        self.logoPosition = logoPosition
        self.value = value
        self.pages = pages
        self.user_id = user_id

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    description = db.Column(db.String())
    logoPosition = db.Column(db.String())
    value = db.Column(db.Integer, nullable=False)
    date_creation = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    pages = db.Column(ARRAY(JSONB), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    page = db.relationship("Pages", backref="surveys")


class Pages(db.Model):
    def __init__(self, name, elements, survey_id):
        self.name = name
        self.elements = elements
        self.survey_id = survey_id

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    elements = db.Column(ARRAY(JSONB), nullable=False)
    survey_id = db.Column(db.Integer, db.ForeignKey("surveys.id"))
    question = db.relationship("Questions", backref="pages")


class Questions(db.Model):
    def __init__(self, type, name, isRequired, title, placeholder, choices, page_id):
        self.type = type
        self.name = name
        self.isRequired = isRequired
        self.title = title
        self.placeholder = placeholder
        self.choices = choices
        self.page_id = page_id

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(), nullable=False)
    name = db.Column(db.String(), nullable=False)
    isRequired = db.Column(db.Boolean(), nullable=True)
    title = db.Column(db.String(), nullable=True)
    placeholder = db.Column(db.String(), nullable=True)
    choices = db.Column(ARRAY(db.String()), nullable=True)
    page_id = db.Column(db.Integer, db.ForeignKey("pages.id"))
    answer = db.relationship("Answers", backref="questions")

    def serialize(self):
        fields = ["_sa_instance_state", "id", "page_id"]
        return {k: v for k, v in self.__dict__.items() if v != None and k not in fields}


class Answers(db.Model):
    def __init__(self, title, answer, question_id, user_id):
        self.title = title
        self.answer = answer
        self.question_id = question_id
        self.user_id = user_id

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    answer = db.Column(db.String(), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("questions.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
