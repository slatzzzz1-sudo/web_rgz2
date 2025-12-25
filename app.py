from flask import Flask, redirect, request, render_template, session, url_for, flash, jsonify, current_app, g
import psycopg2
from psycopg2.extras import RealDictCursor
import sqlite3
import hashlib
import os
from werkzeug.security import generate_password_hash, check_password_hash
from os import path

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'recipe-secret-key-dimasam-2025')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')  # postgres или sqlite

def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='dimasam',
            user='dimasam',
            password='123'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        # SQLite
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database2.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    return conn, cur

def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

def validate_login(login):
    """Логин: лат.буквы, цифры, _, ., - (минимум 3 символа)"""
    return bool(login and len(login) >= 3 and all(c.isalnum() or c in '_.-' for c in login))

def hash_password(password, salt=None):
    """PBKDF2 хеширование с солью"""
    if salt is None:
        salt = os.urandom(32).hex()
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                 salt.encode('utf-8'), 100000).hex()
    return pwd_hash, salt

STUDENT_INFO = "Самойлов Дмитрий Алексеевич, ФБИ-32"

@app.route('/')
def index():
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            ORDER BY r.created_at DESC 
            LIMIT 12
        """)
    else:
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            ORDER BY r.created_at DESC 
            LIMIT 12
        """)
    recipes = cur.fetchall()
    db_close(conn, cur)
    return render_template('index.html', recipes=recipes, student_info=STUDENT_INFO)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', student_info=STUDENT_INFO)

    login_input = request.form.get('login', '').strip()
    password = request.form.get('password', '').strip()
    
    if not (login_input and password):
        return render_template('login.html', error='Заполните все поля', student_info=STUDENT_INFO)
    
    if not validate_login(login_input):
        return render_template('login.html', error='Логин: лат.буквы, цифры, _, ., - (3+)', student_info=STUDENT_INFO)
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE login=%s;", (login_input,))
    else:
        cur.execute("SELECT * FROM users WHERE login=?;", (login_input,))
    
    user = cur.fetchone()
    db_close(conn, cur)
    
    if user:
        # Проверка PBKDF2 хеша
        stored_hash = user['password_hash']
        stored_salt = user['salt']
        pwd_hash, _ = hash_password(password, stored_salt)
        if pwd_hash == stored_hash:
            session['login'] = user['login']
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('recipes'))
    
    return render_template('login.html', error='Неверный логин или пароль', student_info=STUDENT_INFO)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', student_info=STUDENT_INFO)

    login_input = request.form.get('login', '').strip()
    password = request.form.get('password', '').strip()
    
    if not (login_input and password):
        return render_template('register.html', error='Заполните все поля', student_info=STUDENT_INFO)
    
    if not validate_login(login_input) or len(password) < 6:
        return render_template('register.html', error='Логин: лат.буквы/цифры/_.- (3+), пароль: 6+ символов', student_info=STUDENT_INFO)
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT login FROM users WHERE login=%s;", (login_input,))
    else:
        cur.execute("SELECT login FROM users WHERE login=?;", (login_input,))
    
    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Пользователь уже существует', student_info=STUDENT_INFO)
    
    pwd_hash, salt = hash_password(password)
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("INSERT INTO users (login, password_hash, salt) VALUES (%s, %s, %s);", 
                   (login_input, pwd_hash, salt))
    else:
        cur.execute("INSERT INTO users (login, password_hash, salt) VALUES (?, ?, ?);", 
                   (login_input, pwd_hash, salt))
    db_close(conn, cur)
    return render_template('login.html', success='Регистрация успешна! Войдите.', student_info=STUDENT_INFO)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if not session.get('login'):
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('delete_account.html', student_info=STUDENT_INFO)

    if request.form.get('confirm') == 'yes':
        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("DELETE FROM users WHERE id=%s;", (session['user_id'],))
        else:
            cur.execute("DELETE FROM users WHERE id=?;", (session['user_id'],))
        db_close(conn, cur)
        session.clear()
        return redirect(url_for('index'))
    
    flash('Подтвердите удаление аккаунта')
    return render_template('delete_account.html', student_info=STUDENT_INFO)

@app.route('/recipes')
def recipes():
    if not session.get('login'):
        return redirect(url_for('login'))
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT r.*, c.name as category_name, COUNT(ri.ingredient_id) as ingredients_count
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id
            LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id
            GROUP BY r.id, c.name
            ORDER BY r.created_at DESC
        """)
    else:
        cur.execute("""
            SELECT r.*, c.name as category_name, COUNT(ri.ingredient_id) as ingredients_count
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id
            LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id
            GROUP BY r.id, c.name
            ORDER BY r.created_at DESC
        """)
    recipes_list = cur.fetchall()
    db_close(conn, cur)
    return render_template('recipes.html', recipes=recipes_list, student_info=STUDENT_INFO)

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    if not session.get('login'):
        return redirect(url_for('login'))
    
    conn, cur = db_connect()
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            WHERE r.id = %s
        """, (recipe_id,))
    else:
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            WHERE r.id = ?
        """, (recipe_id,))
    
    recipe = cur.fetchone()
    if not recipe:
        db_close(conn, cur)
        return "Рецепт не найден", 404
    
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT i.name, i.unit, ri.quantity 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = %s
        """, (recipe_id,))
        cur.execute("""
            SELECT step_number, description 
            FROM recipe_steps 
            WHERE recipe_id = %s 
            ORDER BY step_number
        """, (recipe_id,))
    else:
        cur.execute("""
            SELECT i.name, i.unit, ri.quantity 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = ?
        """, (recipe_id,))
        cur.execute("""
            SELECT step_number, description 
            FROM recipe_steps 
            WHERE recipe_id = ? 
            ORDER BY step_number
        """, (recipe_id,))
    
    ingredients = cur.fetchall()
    steps = cur.fetchall()
    db_close(conn, cur)
    
    return render_template('recipe_detail.html', recipe=recipe, ingredients=ingredients, 
                         steps=steps, student_info=STUDENT_INFO)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if not session.get('login'):
        return redirect(url_for('login'))
    
    recipes = []
    if request.method == 'POST':
        keywords = [kw.strip() for kw in request.form.get('keywords', '').lower().split() if kw.strip()]
        search_mode = request.form.get('mode', 'any')
        
        conn, cur = db_connect()
        if keywords:
            if search_mode == 'all' and len(keywords) > 1:
                # Все ингредиенты должны быть
                if current_app.config['DB_TYPE'] == 'postgres':
                    query = """
                        SELECT DISTINCT r.*, c.name as category_name
                        FROM recipes r 
                        LEFT JOIN categories c ON r.category_id = c.id
                        JOIN recipe_ingredients ri ON r.id = ri.recipe_id
                        JOIN ingredients i ON ri.ingredient_id = i.id
                        WHERE LOWER(r.title) LIKE %s OR LOWER(i.name) LIKE %s
                        GROUP BY r.id, c.name
                        HAVING COUNT(DISTINCT i.id) >= %s
                    """
                    cur.execute(query, ('%' + '%'.join(keywords) + '%', '%' + '%'.join(keywords) + '%', len(keywords)))
                else:
                    # SQLite упрощенный поиск
                    conditions = ' OR '.join(["LOWER(r.title) LIKE ?" for _ in keywords])
                    args = tuple(['%' + kw + '%' for kw in keywords])
                    cur.execute(f"""
                        SELECT DISTINCT r.*, c.name as category_name
                        FROM recipes r 
                        LEFT JOIN categories c ON r.category_id = c.id
                        WHERE {conditions}
                        ORDER BY r.title
                    """, args)
            else:
                # Хоть один ингредиент
                conditions = ' OR '.join(["LOWER(r.title) LIKE ? OR LOWER(i.name) LIKE ?"] * len(keywords))
                args = tuple(['%' + kw + '%' for kw in keywords] * 2)
                if current_app.config['DB_TYPE'] == 'postgres':
                    cur.execute(f"""
                        SELECT DISTINCT r.*, c.name as category_name
                        FROM recipes r 
                        LEFT JOIN categories c ON r.category_id = c.id
                        LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id
                        LEFT JOIN ingredients i ON ri.ingredient_id = i.id
                        WHERE {conditions}
                        ORDER BY r.title
                    """, args)
                else:
                    conditions = ' OR '.join(["LOWER(r.title) LIKE ?"] * len(keywords))
                    args = tuple(['%' + kw + '%' for kw in keywords])
                    cur.execute(f"""
                        SELECT DISTINCT r.*, c.name as category_name
                        FROM recipes r 
                        LEFT JOIN categories c ON r.category_id = c.id
                        WHERE {conditions}
                        ORDER BY r.title
                    """, args)
            
            recipes = cur.fetchall()
        db_close(conn, cur)
    
    return render_template('search.html', recipes=recipes, student_info=STUDENT_INFO)

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            ORDER BY r.created_at DESC
        """)
    else:
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            ORDER BY r.created_at DESC
        """)
    recipes = cur.fetchall()
    db_close(conn, cur)
    return render_template('admin.html', recipes=recipes, student_info=STUDENT_INFO)

@app.route('/admin/add_recipe', methods=['POST'])
def add_recipe():
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    title = request.form.get('title')
    description = request.form.get('description')
    cooking_time = request.form.get('cooking_time')
    servings = request.form.get('servings')
    category_id = request.form.get('category_id')
    image_path = request.form.get('image_path', '')
    
    if not all([title, cooking_time, servings, category_id]):
        return "Заполните обязательные поля", 400
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (title, description, cooking_time, servings, category_id, image_path))
    else:
        cur.execute("""
            INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (title, description, cooking_time, servings, category_id, image_path))
    db_close(conn, cur)
    return redirect(url_for('admin'))

@app.route('/admin/delete_recipe/<int:recipe_id>', methods=['POST'])
def delete_recipe(recipe_id):
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM recipes WHERE id=%s;", (recipe_id,))
    else:
        cur.execute("DELETE FROM recipes WHERE id=?;", (recipe_id,))
    db_close(conn, cur)
    return redirect(url_for('admin'))

if __name__ == '__main__':
    db_type = app.config['DB_TYPE']  # ✅ СНАЧАЛА получаем значение!
    
    # Создание админ аккаунта при первом запуске
    with app.app_context():
        conn, cur = db_connect()
        if db_type == 'postgres':
            cur.execute("SELECT login FROM users WHERE login=%s;", ('admin',))
        else:
            cur.execute("SELECT login FROM users WHERE login=?;", ('admin',))
        
        if not cur.fetchone():
            pwd_hash, salt = hash_password('admin123')
            if db_type == 'postgres':
                cur.execute("INSERT INTO users (login, password_hash, salt, is_admin) VALUES (%s, %s, %s, %s);",
                           ('admin', pwd_hash, salt, True))
            else:
                cur.execute("INSERT INTO users (login, password_hash, salt, is_admin) VALUES (?, ?, ?, ?);",
                           ('admin', pwd_hash, salt, 1))
            conn.commit()
            
        
        db_close(conn, cur)
    



