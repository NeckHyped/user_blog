from datetime import date
from typing import List
from smtplib import SMTP
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import hashlib
import secrets
import os
from dotenv import load_dotenv

# Loading all variables
load_dotenv()

# Method 1: Hash random bytes
random_bytes = secrets.token_bytes(32)
hash_hex = hashlib.sha256(random_bytes).hexdigest()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

mail_id = os.getenv("ADMIN_EMAIL")
password = os.getenv("ADMIN_PWD")

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    author: Mapped["User"] = relationship(back_populates="posts")
    comments: Mapped[List["Comment"]] = relationship(back_populates="post")

# TODO: Create a User table for all your registered users.
class User(db.Model, UserMixin):
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[List["Comment"]] = relationship(back_populates="author")

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250))

class Comment(db.Model):
    author: Mapped["User"] = relationship(back_populates="comments")
    post: Mapped["BlogPost"] = relationship(back_populates="comments")
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    text: Mapped[str] = mapped_column(String(500), nullable=False)
with app.app_context():
    db.create_all()

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            abort(403)
        return f(*args, **kwargs)
    return wrapper

###
@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()
###

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        email = request.form.get("email")
        password=generate_password_hash(password=request.form.get("password"), salt_length=8, method="pbkdf2:sha256")
        name=request.form.get("name")
        if email in db.session.execute(db.select(User.email).order_by(User.id)).scalars().all():
            flash("Sorry that email is already registered with us, you may log in directly")
            return redirect(url_for('login'))
        else:
            to_add = User(email=email, password=password, name=name)
            db.session.add(to_add)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form=LoginForm()
    if request.method == "POST":
        email=request.form.get("email")
        pwd=request.form.get("password")
        try:
            user = db.session.execute(db.select(User).where(User.email==email)).scalar()
            if user is None:  # Add this check
                flash("Sorry that email is not registered with us, kindly register before logging in")
                return redirect(url_for('register'))
        except AttributeError:
            flash("Sorry that email is not registered with us, kindly register before logging in")
            return redirect(url_for('register'))
        else:
            if check_password_hash(pwhash=user.password, password=pwd):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect password. Try again.")
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@login_required
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    if request.method == "POST":
        if current_user.is_authenticated:
            text = request.form.get("body")
            author = current_user
            author_id = current_user.id
            post = requested_post
            postid = requested_post.id
            db.session.add(Comment(text=text, author=author, author_id=author_id, post=post, post_id=postid))
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        return redirect(url_for('login'))
    form = CommentForm()
    comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars()
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form, comments=comments, url=hash_hex)


# TODO: Use a decorator so only an admin user can create a new post
@admin_only
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@admin_only
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")

@login_required
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        if current_user.is_authenticated:
            phone = request.form["phone"]
            msg = request.form["message"]
            email = request.form["email"]
            name = request.form["name"]
            with SMTP("smtp.gmail.com") as connection_object:
                connection_object.starttls()
                connection_object.login(user=mail_id, password=password)
                connection_object.sendmail(from_addr=email, to_addrs=mail_id, msg=f"Heyy Abhhay," \
                                                                                    f"This is {name}." \
                                                                                    f"My email ID is {email}." \
                                                                                    f"My phone number is {phone}." \
                                                                                    f"{msg}")
            flash("Form submitted successfully!")
        return redirect(url_for('contact'))
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
