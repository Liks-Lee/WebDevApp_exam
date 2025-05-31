# forms.py - файл для описания форм проекта

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, SelectMultipleField, SelectField, FileField, BooleanField
from wtforms.validators import DataRequired, Length, NumberRange

# Форма входа пользователя
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

# Форма добавления/редактирования книги
class BookForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('Описание', validators=[DataRequired()])
    year = IntegerField('Год', validators=[DataRequired(), NumberRange(min=1000, max=2100)])
    publisher = StringField('Издательство', validators=[DataRequired(), Length(max=128)])
    author = StringField('Автор', validators=[DataRequired(), Length(max=128)])
    pages = IntegerField('Страниц', validators=[DataRequired(), NumberRange(min=1)])
    genres = SelectMultipleField('Жанры', coerce=int)
    cover = FileField('Обложка')
    submit = SubmitField('Сохранить')

# Форма добавления рецензии
class ReviewForm(FlaskForm):
    rating = SelectField(
        'Оценка',
        choices=[(5, 'отлично'), (4, 'хорошо'), (3, 'удовлетворительно'), (2, 'неудовлетворительно'), (1, 'плохо'), (0, 'ужасно')],
        coerce=int,
        default=5
    )
    text = TextAreaField('Текст рецензии', validators=[DataRequired()])
    submit = SubmitField('Сохранить')

# Форма регистрации пользователя
class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=4)])
    last_name = StringField('Фамилия', validators=[DataRequired(), Length(max=64)])
    first_name = StringField('Имя', validators=[DataRequired(), Length(max=64)])
    middle_name = StringField('Отчество', validators=[Length(max=64)])
    submit = SubmitField('Зарегистрироваться')
