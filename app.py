from flask import Flask
from config import Config
from models import db
from flask_login import LoginManager
from flask import render_template, redirect, url_for, flash, request, abort, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Role, Book, Genre, Cover, Review, ReviewStatus
from forms import LoginForm, BookForm, ReviewForm, RegisterForm
from werkzeug.security import check_password_hash, generate_password_hash
import os, hashlib, markdown, bleach
from sqlalchemy import func
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def custom_unauthorized():
    flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'error')
    return redirect(url_for('login'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def md5_for_file(file):
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file.read(4096), b""):
        hash_md5.update(chunk)
    file.seek(0)
    return hash_md5.hexdigest()

def sanitize_html(text):
    return bleach.clean(
        markdown.markdown(text),
        tags=list(bleach.sanitizer.ALLOWED_TAGS) + ['p', 'pre', 'span'],
        attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    query = Book.query
    if search:
        query = query.filter(Book.title.ilike(f'%{search}%'))

    books = query.order_by(Book.id.desc()).paginate(page=page, per_page=10)
    for book in books.items:
        book.avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.book_id==book.id, Review.status.has(name='approved')).scalar()
        book.reviews_count = Review.query.filter_by(book_id=book.id, status_id=ReviewStatus.query.filter_by(name='approved').first().id).count()
    return render_template('index.html', books=books, search=search)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))
        flash('Невозможно аутентифицироваться с указанными логином и паролем', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Пользователь с таким логином уже существует', 'error')
        else:
            user_role = Role.query.filter_by(name='user').first()
            user = User(
                username=form.username.data,
                password_hash=generate_password_hash(form.password.data),
                last_name=form.last_name.data,
                first_name=form.first_name.data,
                middle_name=form.middle_name.data,
                role_id=user_role.id
            )
            db.session.add(user)
            db.session.commit()
            flash('Регистрация успешна. Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/book/add', methods=['GET', 'POST'])
@login_required
def add_book():
    if current_user.role.name != 'admin':
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    form = BookForm()
    form.genres.choices = [(g.id, g.name) for g in Genre.query.all()]
    if form.validate_on_submit():
        try:
            safe_description = bleach.clean(form.description.data)
            book = Book(
                title=form.title.data,
                description=safe_description,
                year=form.year.data,
                publisher=form.publisher.data,
                author=form.author.data,
                pages=form.pages.data
            )
            for genre_id in form.genres.data:
                genre = db.session.get(Genre, genre_id)
                if genre:
                    book.genres.append(genre)
            db.session.add(book)
            db.session.flush()

            file = form.cover.data
            if file and hasattr(file, "filename") and file.filename:
                if allowed_file(file.filename):
                    md5 = md5_for_file(file)
                    cover = Cover.query.filter_by(md5_hash=md5).first()
                    if cover:
                        book.cover_id = cover.id
                    else:
                        cover = Cover(
                            filename='',
                            mime_type=file.mimetype,
                            md5_hash=md5
                        )
                        db.session.add(cover)
                        db.session.flush()
                        filename = f"{cover.id}.jpg"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        cover.filename = filename
                        db.session.commit()
                        book.cover_id = cover.id
            db.session.commit()
            flash('Книга успешно добавлена', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            import traceback
            print('Ошибка при добавлении книги:', e)
            traceback.print_exc()
            flash(f'При сохранении данных возникла ошибка: {e}. Проверьте корректность введённых данных.', 'error')
    return render_template('book_form.html', form=form, book=None)

@app.route('/book/<int:book_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = db.session.get(Book, book_id)
    if not book:
        abort(404)
    if current_user.role.name not in ['admin', 'moderator']:
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    form = BookForm(obj=book)
    form.genres.choices = [(g.id, g.name) for g in Genre.query.all()]
    if request.method == 'GET':
        form.genres.data = [g.id for g in book.genres]
    if form.validate_on_submit():
        try:
            book.title = form.title.data
            book.description = bleach.clean(form.description.data)
            book.year = form.year.data
            book.publisher = form.publisher.data
            book.author = form.author.data
            book.pages = form.pages.data
            book.genres = [db.session.get(Genre, gid) for gid in form.genres.data]
            file = form.cover.data
            if file and hasattr(file, "read") and hasattr(file, "filename") and file.filename:
                if allowed_file(file.filename):
                    md5 = md5_for_file(file)
                    cover = Cover.query.filter_by(md5_hash=md5).first()
                    if cover:
                        book.cover_id = cover.id
                    else:
                        if book.cover:
                            old_cover = book.cover
                            if Book.query.filter(Book.cover_id == old_cover.id, Book.id != book.id).count() == 0:
                                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_cover.filename)
                                if os.path.exists(old_path):
                                    os.remove(old_path)
                                db.session.delete(old_cover)
                                db.session.flush()
                        cover = Cover(filename='', mime_type=file.mimetype, md5_hash=md5)
                        db.session.add(cover)
                        db.session.flush()
                        filename = f"{cover.id}.jpg"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        cover.filename = filename
                        db.session.commit()
                        book.cover_id = cover.id
            db.session.commit()
            flash('Книга успешно обновлена', 'success')
            return redirect(url_for('book_view', book_id=book.id))
        except Exception as e:
            db.session.rollback()
            import traceback
            print('Ошибка при обновлении книги:', e)
            traceback.print_exc()
            flash(f'Ошибка при обновлении книги: {e}', 'error')
    return render_template('book_form.html', form=form, book=book)

@app.route('/book/<int:book_id>')
def book_view(book_id):
    book = Book.query.get_or_404(book_id)
    book.description_html = sanitize_html(book.description)
    reviews = Review.query.filter_by(book_id=book.id).join(ReviewStatus).filter(ReviewStatus.name=='approved').order_by(Review.created_at.desc()).all()
    for r in reviews:
        r.text_html = sanitize_html(r.text)
    can_review = False
    if current_user.is_authenticated and current_user.role.name in ['user', 'moderator', 'admin']:
        exists = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
        if not exists:
            can_review = True
    return render_template('book_view.html', book=book, reviews=reviews, can_review=can_review)

@app.route('/book/<int:book_id>/delete')
@login_required
def delete_book(book_id):
    if current_user.role.name != 'admin':
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    book = Book.query.get_or_404(book_id)
    try:
        if book.cover:
            cover_path = os.path.join(app.config['UPLOAD_FOLDER'], book.cover.filename)
            if os.path.exists(cover_path):
                os.remove(cover_path)
        db.session.delete(book)
        db.session.commit()
        flash('Книга удалена', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении книги', 'error')
    return redirect(url_for('index'))

@app.route('/book/<int:book_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(book_id):
    book = Book.query.get_or_404(book_id)
    if Review.query.filter_by(book_id=book.id, user_id=current_user.id).first():
        flash('Вы уже оставляли рецензию на эту книгу', 'error')
        return redirect(url_for('book_view', book_id=book.id))
    form = ReviewForm()
    if form.validate_on_submit():
        try:
            status = ReviewStatus.query.filter_by(name='pending').first()
            review = Review(
                book_id=book.id,
                user_id=current_user.id,
                rating=form.rating.data,
                text=form.text.data,
                status_id=status.id
            )
            db.session.add(review)
            db.session.commit()
            flash('Рецензия отправлена на модерацию', 'success')
            return redirect(url_for('book_view', book_id=book.id))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при добавлении рецензии', 'error')
    return render_template('review_form.html', form=form)

@app.route('/my-reviews')
@login_required
def my_reviews():
    reviews = Review.query.filter_by(user_id=current_user.id).order_by(Review.created_at.desc()).all()
    for r in reviews:
        r.text_html = sanitize_html(r.text)
    return render_template('my_reviews.html', reviews=reviews)

@app.route('/moderate')
@login_required
def moderate():
    if current_user.role.name != 'moderator':
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    status = ReviewStatus.query.filter_by(name='pending').first()
    reviews = Review.query.filter_by(status_id=status.id).order_by(Review.created_at).paginate(page=page, per_page=10)
    for r in reviews.items:
        r.text_html = sanitize_html(r.text)
    return render_template('moderate.html', reviews=reviews)

@app.route('/moderate/<int:review_id>', methods=['GET', 'POST'])
@login_required
def moderate_review(review_id):
    if current_user.role.name != 'moderator':
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    review = Review.query.get_or_404(review_id)
    review.text_html = sanitize_html(review.text)
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'approve':
                review.status_id = ReviewStatus.query.filter_by(name='approved').first().id
            elif action == 'reject':
                review.status_id = ReviewStatus.query.filter_by(name='rejected').first().id
            db.session.commit()
            flash('Статус рецензии обновлён', 'success')
            return redirect(url_for('moderate'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении статуса', 'error')
    return render_template('moderate_review.html', review=review)

class UserEditForm(FlaskForm):
    last_name = StringField('Фамилия', validators=[DataRequired(), Length(max=64)])
    first_name = StringField('Имя', validators=[DataRequired(), Length(max=64)])
    middle_name = StringField('Отчество', validators=[Length(max=64)])
    role_id = SelectField('Роль', coerce=int)
    password = PasswordField('Новый пароль')
    submit = SubmitField('Сохранить')

class UserAddForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=4)])
    last_name = StringField('Фамилия', validators=[DataRequired(), Length(max=64)])
    first_name = StringField('Имя', validators=[DataRequired(), Length(max=64)])
    middle_name = StringField('Отчество', validators=[Length(max=64)])
    role_id = SelectField('Роль', coerce=int)
    submit = SubmitField('Добавить')

@app.route('/users')
@login_required
def users():
    if current_user.role.name != 'admin':
        abort(403)
    users = User.query.order_by(User.id).all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role.name != 'admin':
        abort(403)
    form = UserAddForm()
    form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Пользователь с таким логином уже существует', 'error')
        else:
            user = User(
                username=form.username.data,
                password_hash=generate_password_hash(form.password.data),
                last_name=form.last_name.data,
                first_name=form.first_name.data,
                middle_name=form.middle_name.data,
                role_id=form.role_id.data
            )
            db.session.add(user)
            db.session.commit()
            flash('Пользователь добавлен', 'success')
            return redirect(url_for('users'))
    return render_template('user_add.html', form=form)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role.name != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)
    form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]
    if form.validate_on_submit():
        user.last_name = form.last_name.data
        user.first_name = form.first_name.data
        user.middle_name = form.middle_name.data
        user.role_id = form.role_id.data
        if form.password.data:
            user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Пользователь обновлён', 'success')
        return redirect(url_for('users'))
    return render_template('user_edit.html', form=form, user=user)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role.name != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Нельзя удалить самого себя.', 'error')
        return redirect(url_for('users'))
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удалён', 'success')
    return redirect(url_for('users'))

@app.errorhandler(401)
def unauthorized(e):
    flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'error')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    flash('У вас недостаточно прав для выполнения данного действия', 'error')
    return redirect(url_for('index'))


@app.route('/all-reviews')
@login_required
def all_reviews():
    if current_user.role.name != 'admin':
        abort(403)
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    for r in reviews:
        r.text_html = sanitize_html(r.text)
    return render_template('all_reviews.html', reviews=reviews)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        from werkzeug.security import generate_password_hash
        from models import User, Role, ReviewStatus, Genre
        roles_data = [
            ('admin', 'Администратор: полный доступ'),
            ('moderator', 'Модератор: редактирование книг, модерация рецензий'),
            ('user', 'Пользователь: может оставлять рецензии')
        ]
        for name, desc in roles_data:
            if not Role.query.filter_by(name=name).first():
                db.session.add(Role(name=name, description=desc))
        db.session.commit()
        users_data = [
            ('admin', 'admin', 'Админ', 'Админ', '', 'admin'),
            ('moder', 'moder', 'Модер', 'Модератор', '', 'moderator'),
            ('user', 'user', 'Пользователь', 'Обычный', '', 'user')
        ]
        for username, password, last_name, first_name, middle_name, role_name in users_data:
            role = Role.query.filter_by(name=role_name).first()
            if role and not User.query.filter_by(username=username).first():
                user = User(
                    username=username,
                    password_hash=generate_password_hash(password),
                    last_name=last_name,
                    first_name=first_name,
                    middle_name=middle_name,
                    role_id=role.id
                )
                db.session.add(user)
        db.session.commit()
        for status_name in ['pending', 'approved', 'rejected']:
            if not ReviewStatus.query.filter_by(name=status_name).first():
                db.session.add(ReviewStatus(name=status_name))
        db.session.commit()
        default_genres = [
            'Фантастика', 'Детектив', 'Роман', 'Поэзия', 'Научная литература',
            'Приключения', 'Фэнтези', 'История', 'Биография', 'Драма',
            'Триллер', 'Ужасы', 'Комедия', 'Психология', 'Детская литература',
            'Энциклопедия', 'Публицистика', 'Мемуары', 'Любовный роман', 'Саморазвитие'
        ]
        for genre_name in default_genres:
            if not Genre.query.filter_by(name=genre_name).first():
                db.session.add(Genre(name=genre_name))
        db.session.commit()
    app.run(debug=True)
