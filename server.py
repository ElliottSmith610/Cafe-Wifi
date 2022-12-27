from flask import Flask, request, redirect, url_for, render_template, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import *
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import UnmappedInstanceError
from wtforms import StringField, BooleanField, FloatField, SubmitField, SelectField, PasswordField
from wtforms.validators import DataRequired, Email
from functools import wraps

# TODO: flask_wtf.Recaptcha ?
# TODO: generate api key for user when they register

app = Flask(__name__)
app.config["SECRET_KEY"] = "Banana"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cafes.db"
db = SQLAlchemy(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class AddCafeForm(FlaskForm):
    name = StringField("name", validators=[DataRequired()])
    map_url = StringField("map_url", validators=[DataRequired()])
    img_url = StringField("img_url", validators=[DataRequired()])
    location = StringField("location", validators=[DataRequired()], render_kw={"placeholder": "Google maps URL"})
    has_sockets = SelectField("has_sockets", validators=[DataRequired()], choices=["Yes", "No"])
    has_toilet = SelectField("has_toilet", validators=[DataRequired()], choices=["Yes", "No"])
    has_wifi = SelectField("has_wifi", validators=[DataRequired()], choices=["Yes", "No"])
    can_take_calls = SelectField("can_take_calls", validators=[DataRequired()], choices=["Yes", "No"])
    seats = StringField("seats", validators=[DataRequired()])
    coffee_price = StringField("coffee_price", validators=[DataRequired()])
    submit = SubmitField("Submit")


class DeleteCafeForm(FlaskForm):
    confirm = StringField("Confirm", validators=[DataRequired()],
                          render_kw={"placeholder": "Type 'confirm' to delete cafe"})
    submit = SubmitField("Submit")


class Cafes(db.Model):
    __tablename__ = "cafe"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    map_url = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)

    def to_dict(self):
        """ Returns the cafe as a dictionary, with all the values as strings """
        return {column.name: str(getattr(self, column.name)) for column in self.__table__.columns}

# with app.app_context():
#     db.create_all()

def to_bool(value):
    """ Returns a Boolean value if """
    value = value.lower()
    valid = {'true': True, 't': True, '1': True, 'yes': True,
             'false': False, 'f': False, '0': False, 'no': False, }
    if value in valid.keys():
        return valid[value]


def to_choice(value):
    if value:
        return "Yes"
    else:
        return "No"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Website Version, possible to combine with api code??
@app.route("/")
def home():
    all_cafes_query = db.session.query(Cafes).all()
    all_cafes = [cafe.to_dict() for cafe in all_cafes_query]
    return render_template("index.html", all_cafes=all_cafes)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit() and form.password.data == form.confirm.data:
        new_user = User()
        new_user.email = form.email.data
        if User.query.filter_by(email=new_user.email).first():
            # TODO: Flash
            return redirect(url_for('login'))
        new_user.name = form.name.data
        password = form.password.data

        salted_and_hashed_password = generate_password_hash(password=password,
                                                            method='pbkdf2:sha256',
                                                            salt_length=8, )
        new_user.password = salted_and_hashed_password
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            # TODO: Flash incorrect credentials
            pass
    return render_template('register.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/add", methods=["GET", "POST"])
def add_cafe():
    form = AddCafeForm()
    if form.validate_on_submit():
        new_cafe = Cafes(
            name=request.form.get("name"),
            map_url=request.form.get("map_url"),
            img_url=request.form.get("img_url"),
            location=request.form.get("location"),
            has_sockets=to_bool(request.form.get("has_sockets")),
            has_toilet=to_bool(request.form.get("has_toilet")),
            has_wifi=to_bool(request.form.get("has_wifi")),
            can_take_calls=to_bool(request.form.get("can_take_calls")),
            seats=request.form.get("seats"),
            coffee_price=request.form.get("coffee_price"),
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("home"))

    return render_template("add.html", form=form)


@app.route("/edit/<int:cafe_id>", methods=["GET", "POST"])
@login_required
def edit_cafe(cafe_id):
    cafe_to_edit = db.session.get(Cafes, cafe_id)
    editform = AddCafeForm(
        name=cafe_to_edit.name,
        map_url=cafe_to_edit.map_url,
        img_url=cafe_to_edit.img_url,
        location=cafe_to_edit.location,
        has_sockets=to_choice(cafe_to_edit.has_sockets),
        has_toilet=to_choice(cafe_to_edit.has_toilet),
        has_wifi=to_choice(cafe_to_edit.has_wifi),
        can_take_calls=to_choice(cafe_to_edit.can_take_calls),
        seats=cafe_to_edit.seats,
        coffee_price=cafe_to_edit.coffee_price,
    )
    if editform.validate_on_submit():
        cafe_to_edit.name = editform.name.data
        cafe_to_edit.map_url = editform.map_url.data
        cafe_to_edit.img_url = editform.img_url.data
        cafe_to_edit.location = editform.location.data
        cafe_to_edit.has_sockets = to_bool(editform.has_sockets.data)
        cafe_to_edit.has_toilet = to_bool(editform.has_toilet.data)
        cafe_to_edit.has_wifi = to_bool(editform.has_wifi.data)
        cafe_to_edit.can_take_calls = to_bool(editform.can_take_calls.data)
        cafe_to_edit.seats = editform.seats.data
        cafe_to_edit.coffee_price = editform.coffee_price.data
        cafe_to_edit.verified = True
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("edit.html", form=editform, cafe=cafe_to_edit.name)


@app.route("/delete/<int:cafe_id>", methods=["GET", "POST", "DELETE"])
@login_required
def delete_cafe(cafe_id):
    form = DeleteCafeForm()
    cafe_to_delete = db.session.get(Cafes, cafe_id)
    if form.validate_on_submit():
        if form.confirm.data.lower() == "confirm":
            db.session.delete(cafe_to_delete)
            db.session.commit()
            return redirect(url_for("home"))

    return render_template("delete.html", form=form, cafe=cafe_to_delete.name)


# API Version
def authed_user(func):
    # TODO: check for api key in a database rather than a static "SecretKey"
    #  Check API-key matches Username
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None
        if "api-key" in request.headers:
            token = request.headers['api-key']
        if not token:
            return jsonify({"message": "A valid token is missing!"}), 401
        if token == "SecretKey":
            return func(*args, **kwargs)
        else:
            return jsonify({"message": "Invalid token!"}), 401

    return wrapper


@app.route("/cafes/all", methods=["GET"])
def api_all_cafes():
    all_cafes_query = db.session.query(Cafes).all()
    all_cafes = [cafe.to_dict() for cafe in all_cafes_query]
    return jsonify(cafes=all_cafes)


@app.route("/cafes/add", methods=["POST"])
@authed_user
def api_add_cafe():
    new_cafe = Cafes(
        # name=request.args["name"],
        name=request.form.get("name"),
        map_url=request.form.get("map_url"),
        img_url=request.form.get("img_url"),
        location=request.form.get("location"),
        seats=request.form.get("seats"),
        has_toilet=to_bool(request.form.get("has_toilet")),
        has_wifi=to_bool(request.form.get("has_wifi")),
        has_sockets=to_bool(request.form.get("has_sockets")),
        can_take_calls=to_bool(request.form.get("can_take_calls")),
        coffee_price=request.form.get("coffee_price"), )
    try:
        db.session.add(new_cafe)
        db.session.commit()
        response = {"success": f"Successfully added {new_cafe.name}"}
    except IntegrityError:
        db.session.rollback()
        response = {"error": "There was an error adding new cafe"}
    return jsonify(response=response)


@app.route("/cafes/update", methods=["GET", "PATCH"])
@authed_user
def update_cafe():
    params = request.form.to_dict()
    valid_columns = {}
    for column in Cafes.__table__.columns:
        valid_columns[str(column.name)] = str(column.type)
    attributes_to_update = {k: v for k, v in params.items() if k in valid_columns.keys()}

    try:
        cafe_to_update = db.session.get(Cafes, params['id'])
        for key, value in attributes_to_update.items():
            if value == "":
                raise ValueError
            elif valid_columns[key] == "BOOLEAN":
                setattr(cafe_to_update, key, to_bool(value))
            else:
                setattr(cafe_to_update, key, value)
        cafe_to_update.verified = True
        db.session.commit()
        return jsonify(success={"Success": f"Successfully updated {cafe_to_update.name}"}), 200
    except ValueError:
        return jsonify(error={"Error": "Empty value submitted"}), 400
    except UnmappedInstanceError:
        return jsonify(error={"Not found": "Sorry a cafe with that id was not found in the database"}), 404


@app.route("/cafes/delete", methods=["DELETE"])
@authed_user
def api_delete():
    params = request.form.to_dict()
    try:
        cafe_to_delete = db.session.get(Cafes, params['id'])
        db.session.delete(cafe_to_delete)
        db.session.commit()
        return jsonify(success={"Success": f"Successfully deleted {cafe_to_delete.name}"}), 200
    except UnmappedInstanceError:
        return jsonify(error={"Not found": "Sorry a cafe with that id was not found in the database"}), 404


if __name__ == "__main__":
    app.run(debug=True)
