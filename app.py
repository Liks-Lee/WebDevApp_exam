# app.py - основной файл приложения Flask

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
    # Обработчик для неавторизованных пользователей
    flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'error')
    return redirect(url_for('login'))

# Вспомогательная функция: проверка расширения файла
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Вспомогательная функция: вычисление md5-хеша файла
def md5_for_file(file):
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file.read(4096), b""):
        hash_md5.update(chunk)
    file.seek(0)
    return hash_md5.hexdigest()

# Вспомогательная функция: очистка и безопасное преобразование текста в HTML
def sanitize_html(text):
    return bleach.clean(
        markdown.markdown(text),
        tags=list(bleach.sanitizer.ALLOWED_TAGS) + ['p', 'pre', 'span'],
        attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES
    )

# Загрузка пользователя для flask-login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Главная страница со списком книг и поиском
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    query = Book.query
    if search:
        query = query.filter(Book.title.ilike(f'%{search}%'))
    # Сортировка по id (дате добавления) по убыванию — новые книги сверху
    books = query.order_by(Book.id.desc()).paginate(page=page, per_page=10)
    for book in books.items:
        # Средняя оценка и количество рецензий для каждой книги
        book.avg_rating = db.session.query(func.avg(Review.rating)).filter(Review.book_id==book.id, Review.status.has(name='approved')).scalar()
        book.reviews_count = Review.query.filter_by(book_id=book.id, status_id=ReviewStatus.query.filter_by(name='approved').first().id).count()
    return render_template('index.html', books=books, search=search)

# Вход пользователя
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

# Выход пользователя
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Регистрация нового пользователя
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

# Добавление новой книги (только для администратора)
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
            # Алгоритм загрузки обложки 
            file = form.cover.data
            if file and hasattr(file, "filename") and file.filename:
                if allowed_file(file.filename):
                    md5 = md5_for_file(file)
                    cover = Cover.query.filter_by(md5_hash=md5).first()
                    if cover:
                        book.cover_id = cover.id
                    else:
                        cover = Cover(
                            filename='',  # временно
                            mime_type=file.mimetype,
                            md5_hash=md5,
                            book_id=book.id
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
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'error')
    return render_template('book_form.html', form=form, book=None)

# Редактирование книги (админ/модератор)
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
            if file and allowed_file(file.filename):
                md5 = md5_for_file(file)
                cover = Cover.query.filter_by(md5_hash=md5).first()
                if cover:
                    book.cover_id = cover.id
                else:
                    # Удалить старую обложку-файл, если была и не используется другими книгами
                    if book.cover:
                        old_cover = book.cover
                        # Если ни одна другая книга не использует эту обложку
                        if Book.query.filter(Book.cover_id == old_cover.id, Book.id != book.id).count() == 0:
                            old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_cover.filename)
                            if os.path.exists(old_path):
                                os.remove(old_path)
                            db.session.delete(old_cover)
                            db.session.flush()
                    cover = Cover(filename='', mime_type=file.mimetype, md5_hash=md5, book_id=book.id)
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
            flash('Ошибка при обновлении книги', 'error')
    return render_template('book_form.html', form=form, book=book)

# Просмотр книги и рецензий
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

# Удаление книги (только для администратора)
@app.route('/book/<int:book_id>/delete')
@login_required
def delete_book(book_id):
    if current_user.role.name != 'admin':
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('index'))
    book = Book.query.get_or_404(book_id)
    try:
        # Удалить файл обложки, если есть
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

# Добавление рецензии к книге
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

# Просмотр своих рецензий
@app.route('/my-reviews')
@login_required
def my_reviews():
    reviews = Review.query.filter_by(user_id=current_user.id).order_by(Review.created_at.desc()).all()
    for r in reviews:
        r.text_html = sanitize_html(r.text)
    return render_template('my_reviews.html', reviews=reviews)

# Модерация рецензий (только для модератора)
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

# Модерация конкретной рецензии
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

# Формы для управления пользователями (админ)
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

# Список пользователей (только для администратора)
@app.route('/users')
@login_required
def users():
    if current_user.role.name != 'admin':
        abort(403)
    users = User.query.order_by(User.id).all()
    return render_template('users.html', users=users)

# Добавление пользователя (только для администратора)
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

# Редактирование пользователя (только для администратора)
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

# Удаление пользователя (только для администратора)
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

# Обработка ошибок доступа
@app.errorhandler(401)
def unauthorized(e):
    flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'error')
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    flash('У вас недостаточно прав для выполнения данного действия', 'error')
    return redirect(url_for('index'))

# Просмотр всех рецензий (только для администратора)
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
        # Создать роли, если нет
        roles_data = [
            ('admin', 'Администратор: полный доступ'),
            ('moderator', 'Модератор: редактирование книг, модерация рецензий'),
            ('user', 'Пользователь: может оставлять рецензии')
        ]
        for name, desc in roles_data:
            if not Role.query.filter_by(name=name).first():
                db.session.add(Role(name=name, description=desc))
        db.session.commit()
        # Создать пользователей для всех ролей
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
        # Добавить статусы рецензий, если их нет
        for status_name in ['pending', 'approved', 'rejected']:
            if not ReviewStatus.query.filter_by(name=status_name).first():
                db.session.add(ReviewStatus(name=status_name))
        db.session.commit()
        # Добавить жанры, если их нет
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
        # Добавить 30 реальных книг с обложками (пример кода закомментирован)
        # import shutil
        #
        # demo_books = [
        #     {
        #         "title": "Война и мир",
        #         "description": "Роман-эпопея Льва Толстого о судьбах людей на фоне войны 1812 года.",
        #         "year": 1869,
        #         "publisher": "Русский Вестник",
        #         "author": "Лев Толстой",
        #         "pages": 1225,
        #         "genres": ["Роман", "Классика", "История"],
        #         "cover_file": "book1.jpg"
        #     },
        #     {
        #         "title": "Преступление и наказание",
        #         "description": "Психологический роман Фёдора Достоевского о преступлении и раскаянии.",
        #         "year": 1866,
        #         "publisher": "Русский Вестник",
        #         "author": "Фёдор Достоевский",
        #         "pages": 671,
        #         "genres": ["Роман", "Драма", "Классика"],
        #         "cover_file": "book2.jpg"
        #     },
        #     {
        #         "title": "Мастер и Маргарита",
        #         "description": "Мистический роман Михаила Булгакова о добре, зле и любви.",
        #         "year": 1967,
        #         "publisher": "Издательство Художественная литература",
        #         "author": "Михаил Булгаков",
        #         "pages": 480,
        #         "genres": ["Роман", "Мистика", "Классика"],
        #         "cover_file": "book3.jpg"
        #     },
        #     {
        #         "title": "Гарри Поттер и философский камень",
        #         "description": "Первая книга о приключениях Гарри Поттера.",
        #         "year": 1997,
        #         "publisher": "Bloomsbury",
        #         "author": "Дж. К. Роулинг",
        #         "pages": 320,
        #         "genres": ["Фэнтези", "Приключения", "Детская литература"],
        #         "cover_file": "book4.jpg"
        #     },
        #     {
        #         "title": "1984",
        #         "description": "Антиутопия Джорджа Оруэлла о тоталитарном будущем.",
        #         "year": 1949,
        #         "publisher": "Secker & Warburg",
        #         "author": "Джордж Оруэлл",
        #         "pages": 328,
        #         "genres": ["Антиутопия", "Классика", "Политика"],
        #         "cover_file": "book5.jpg"
        #     },
        #     {
        #         "title": "Унесённые ветром",
        #         "description": "Исторический роман о любви и войне в США.",
        #         "year": 1936,
        #         "publisher": "Macmillan",
        #         "author": "Маргарет Митчелл",
        #         "pages": 1037,
        #         "genres": ["Роман", "История", "Драма"],
        #         "cover_file": "book6.jpg"
        #     },
        #     {
        #         "title": "Анна Каренина",
        #         "description": "Трагическая история любви Анны Карениной.",
        #         "year": 1877,
        #         "publisher": "Русский Вестник",
        #         "author": "Лев Толстой",
        #         "pages": 864,
        #         "genres": ["Роман", "Классика", "Драма"],
        #         "cover_file": "book7.jpg"
        #     },
        #     {
        #         "title": "Три товарища",
        #         "description": "Роман о дружбе и любви в послевоенной Германии.",
        #         "year": 1936,
        #         "publisher": "Ullstein Verlag",
        #         "author": "Эрих Мария Ремарк",
        #         "pages": 496,
        #         "genres": ["Роман", "Драма", "Классика"],
        #         "cover_file": "book8.jpg"
        #     },
        #     {
        #         "title": "Гордость и предубеждение",
        #         "description": "Классический роман о любви и предрассудках.",
        #         "year": 1813,
        #         "publisher": "T. Egerton",
        #         "author": "Джейн Остин",
        #         "pages": 432,
        #         "genres": ["Роман", "Классика", "Любовный роман"],
        #         "cover_file": "book9.jpg"
        #     },
        #     {
        #         "title": "Шерлок Холмс: Собака Баскервилей",
        #         "description": "Детектив о расследовании загадочного убийства.",
        #         "year": 1902,
        #         "publisher": "George Newnes",
        #         "author": "Артур Конан Дойл",
        #         "pages": 256,
        #         "genres": ["Детектив", "Классика", "Триллер"],
        #         "cover_file": "book10.jpg"
        #     },
        #     {
        #         "title": "Маленький принц",
        #         "description": "Философская сказка для взрослых и детей.",
        #         "year": 1943,
        #         "publisher": "Reynal & Hitchcock",
        #         "author": "Антуан де Сент-Экзюпери",
        #         "pages": 96,
        #         "genres": ["Сказка", "Философия", "Детская литература"],
        #         "cover_file": "book11.jpg"
        #     },
        #     {
        #         "title": "Алхимик",
        #         "description": "Притча о поиске своего пути.",
        #         "year": 1988,
        #         "publisher": "HarperCollins",
        #         "author": "Пауло Коэльо",
        #         "pages": 208,
        #         "genres": ["Роман", "Философия", "Саморазвитие"],
        #         "cover_file": "book12.jpg"
        #     },
        #     {
        #         "title": "Двенадцать стульев",
        #         "description": "Сатирический роман о поисках сокровищ.",
        #         "year": 1928,
        #         "publisher": "Земля и фабрика",
        #         "author": "Илья Ильф, Евгений Петров",
        #         "pages": 320,
        #         "genres": ["Комедия", "Приключения", "Классика"],
        #         "cover_file": "book13.jpg"
        #     },
        #     {
        #         "title": "Портрет Дориана Грея",
        #         "description": "Роман о молодости, красоте и морали.",
        #         "year": 1890,
        #         "publisher": "Lippincott's Monthly Magazine",
        #         "author": "Оскар Уайльд",
        #         "pages": 304,
        #         "genres": ["Роман", "Классика", "Мистика"],
        #         "cover_file": "book14.jpg"
        #     },
        #     {
        #         "title": "Три мушкетёра",
        #         "description": "Приключения мушкетёров во Франции XVII века.",
        #         "year": 1844,
        #         "publisher": "Le Siècle",
        #         "author": "Александр Дюма",
        #         "pages": 672,
        #         "genres": ["Приключения", "История", "Классика"],
        #         "cover_file": "book15.jpg"
        #     },
        #     {
        #         "title": "Пикник на обочине",
        #         "description": "Фантастический роман братьев Стругацких.",
        #         "year": 1972,
        #         "publisher": "Аврора",
        #         "author": "Аркадий и Борис Стругацкие",
        #         "pages": 224,
        #         "genres": ["Фантастика", "Классика", "Драма"],
        #         "cover_file": "book16.jpg"
        #     },
        #     {
        #         "title": "Над пропастью во ржи",
        #         "description": "Роман о взрослении и поиске себя.",
        #         "year": 1951,
        #         "publisher": "Little, Brown and Company",
        #         "author": "Джером Д. Сэлинджер",
        #         "pages": 277,
        #         "genres": ["Роман", "Классика", "Драма"],
        #         "cover_file": "book17.jpg"
        #     },
        #     {
        #         "title": "Мёртвые души",
        #         "description": "Поэма в прозе о жизни помещиков и чиновников.",
        #         "year": 1842,
        #         "publisher": "Современник",
        #         "author": "Николай Гоголь",
        #         "pages": 352,
        #         "genres": ["Роман", "Классика", "Сатира"],
        #         "cover_file": "book18.jpg"
        #     },
        #     {
        #         "title": "Дон Кихот",
        #         "description": "Роман о приключениях рыцаря Дон Кихота.",
        #         "year": 1605,
        #         "publisher": "Francisco de Robles",
        #         "author": "Мигель де Сервантес",
        #         "pages": 863,
        #         "genres": ["Роман", "Классика", "Приключения"],
        #         "cover_file": "book19.jpg"
        #     },
        #     {
        #         "title": "Зелёная миля",
        #         "description": "Мистический роман о чудесах и справедливости.",
        #         "year": 1996,
        #         "publisher": "Signet Books",
        #         "author": "Стивен Кинг",
        #         "pages": 480,
        #         "genres": ["Драма", "Мистика", "Триллер"],
        #         "cover_file": "book20.jpg"
        #     },
        #     {
        #         "title": "Властелин колец: Братство Кольца",
        #         "description": "Фэнтези-эпопея о борьбе добра и зла.",
        #         "year": 1954,
        #         "publisher": "Allen & Unwin",
        #         "author": "Дж. Р. Р. Толкин",
        #         "pages": 423,
        #         "genres": ["Фэнтези", "Приключения", "Эпос"],
        #         "cover_file": "book21.jpg"
        #     },
        #     {
        #         "title": "Дюна",
        #         "description": "Фантастический роман о борьбе за власть на пустынной планете.",
        #         "year": 1965,
        #         "publisher": "Chilton Books",
        #         "author": "Фрэнк Герберт",
        #         "pages": 544,
        #         "genres": ["Фантастика", "Фэнтези", "Эпос"],
        #         "cover_file": "book22.jpg"
        #     },
        #     {
        #         "title": "Отцы и дети",
        #         "description": "Роман о конфликте поколений в России XIX века.",
        #         "year": 1862,
        #         "publisher": "Современник",
        #         "author": "Иван Тургенев",
        #         "pages": 320,
        #         "genres": ["Роман", "Классика", "Драма"],
        #         "cover_file": "book23.jpg"
        #     },
        #     {
        #         "title": "Человек-невидимка",
        #         "description": "Фантастический роман о человеке, ставшем невидимым.",
        #         "year": 1897,
        #         "publisher": "C. Arthur Pearson",
        #         "author": "Герберт Уэллс",
        #         "pages": 208,
        #         "genres": ["Фантастика", "Классика", "Драма"],
        #         "cover_file": "book24.jpg"
        #     },
        #     {
        #         "title": "Портрет художника в юности",
        #         "description": "Роман о взрослении и поиске себя.",
        #         "year": 1916,
        #         "publisher": "B. W. Huebsch",
        #         "author": "Джеймс Джойс",
        #         "pages": 304,
        #         "genres": ["Роман", "Классика", "Психология"],
        #         "cover_file": "book25.jpg"
        #     },
        #     {
        #         "title": "Старик и море",
        #         "description": "Повесть о борьбе человека с природой.",
        #         "year": 1952,
        #         "publisher": "Charles Scribner's Sons",
        #         "author": "Эрнест Хемингуэй",
        #         "pages": 127,
        #         "genres": ["Роман", "Классика", "Драма"],
        #         "cover_file": "book26.jpg"
        #     },
        #     {
        #         "title": "Тихий Дон",
        #         "description": "Эпопея о судьбе казаков на фоне революции.",
        #         "year": 1940,
        #         "publisher": "Советский писатель",
        #         "author": "Михаил Шолохов",
        #         "pages": 1600,
        #         "genres": ["Роман", "Классика", "История"],
        #         "cover_file": "book27.jpg"
        #     },
        #     {
        #         "title": "Путешествие на край ночи",
        #         "description": "Роман о Первой мировой войне и жизни во Франции.",
        #         "year": 1932,
        #         "publisher": "Denoël et Steele",
        #         "author": "Луи-Фердинанд Селин",
        #         "pages": 624,
        #         "genres": ["Роман", "Классика", "Драма"],
        #         "cover_file": "book28.jpg"
        #     },
        #     {
        #         "title": "Маленькие женщины",
        #         "description": "Роман о взрослении четырёх сестёр.",
        #         "year": 1868,
        #         "publisher": "Roberts Brothers",
        #         "author": "Луиза Мэй Олкотт",
        #         "pages": 759,
        #         "genres": ["Роман", "Классика", "Детская литература"],
        #         "cover_file": "book29.jpg"
        #     },
        #     {
        #         "title": "Питер Пэн",
        #         "description": "Сказка о мальчике, который не хотел взрослеть.",
        #         "year": 1911,
        #         "publisher": "Hodder & Stoughton",
        #         "author": "Джеймс Мэтью Барри",
        #         "pages": 240,
        #         "genres": ["Сказка", "Детская литература", "Приключения"],
        #         "cover_file": "book30.jpg"
        #     }
        # ]
        #
        # for idx, book_data in enumerate(demo_books, 1):
        #     if not Book.query.filter_by(title=book_data["title"]).first():
        #         book = Book(
        #             title=book_data["title"],
        #             description=book_data["description"],
        #             year=book_data["year"],
        #             publisher=book_data["publisher"],
        #             author=book_data["author"],
        #             pages=book_data["pages"]
        #         )
        #         # Жанры
        #         for genre_name in book_data["genres"]:
        #             genre = Genre.query.filter_by(name=genre_name).first()
        #             if genre:
        #                 book.genres.append(genre)
        #         db.session.add(book)
        #         db.session.flush()
        #         # Обложка
        #         src_path = os.path.join(app.root_path, "static", "covers", book_data["cover_file"])
        #         dst_filename = f"{book.id}.jpg"
        #         dst_path = os.path.join(app.config['UPLOAD_FOLDER'], dst_filename)
        #         if os.path.exists(src_path):
        #             shutil.copyfile(src_path, dst_path)
        #             cover = Cover(
        #                 filename=dst_filename,
        #                 mime_type="image/jpeg",
        #                 md5_hash=hashlib.md5(open(dst_path, "rb").read()).hexdigest(),
        #                 book_id=book.id
        #             )
        #             db.session.add(cover)
        #         db.session.commit()
    app.run(debug=True)
