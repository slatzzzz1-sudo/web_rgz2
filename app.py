from flask import Flask, redirect, request, render_template, session, url_for, flash, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import sqlite3
import hashlib
import os
from os import path
import random  # Для генерации данных

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'recipe-secret-key-dimasam-2025')

# Путь к SQLite-файлу
BASE_DIR = path.dirname(path.abspath(__file__))
SQLITE_DB_PATH = path.join(BASE_DIR, "database2.db")

def db_connect():
    if os.environ.get('USE_DB') == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='dimasam',
            user='dimasam',
            password='123'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
        app.config['DB_TYPE'] = 'postgres'
        print("Подключено к PostgreSQL (dimasam)")
        return conn, cur
    else:
        conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        app.config['DB_TYPE'] = 'sqlite'
        print(f"Подключено к SQLite: {SQLITE_DB_PATH}")
        return conn, cur

def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

def validate_login(login):
    return bool(login and len(login) >= 3 and all(c.isalnum() or c in '_.-' for c in login))

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32).hex()
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), 
                                   salt.encode('utf-8'), 100000).hex()
    return pwd_hash, salt

STUDENT_INFO = "Самойлов Дмитрий Алексеевич, ФБИ-32"

@app.route('/')
def index():
    conn, cur = db_connect()
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
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE login=%s;", (login_input,))
    else:
        cur.execute("SELECT * FROM users WHERE login=?;", (login_input,))
    
    user = cur.fetchone()
    db_close(conn, cur)
    
    if user:
        stored_hash = user['password_hash']
        stored_salt = user['salt']
        pwd_hash, _ = hash_password(password, stored_salt)
        if pwd_hash == stored_hash:
            session['login'] = user['login']
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
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
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT login FROM users WHERE login=%s;", (login_input,))
    else:
        cur.execute("SELECT login FROM users WHERE login=?;", (login_input,))
    
    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Пользователь уже существует', student_info=STUDENT_INFO)
    
    pwd_hash, salt = hash_password(password)
    if app.config['DB_TYPE'] == 'postgres':
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
        if app.config['DB_TYPE'] == 'postgres':
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

@app.route('/api/recipes', methods=['GET'])
def api_recipes():
    conn, cur = db_connect()
    cur.execute("""
        SELECT r.*, c.name as category_name
        FROM recipes r 
        LEFT JOIN categories c ON r.category_id = c.id
        ORDER BY r.created_at DESC
    """)
    recipes = cur.fetchall()
    db_close(conn, cur)
    return jsonify([dict(r) for r in recipes])

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    if not session.get('login'):
        return redirect(url_for('login'))
    
    conn, cur = db_connect()
    
    param = (recipe_id,)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            WHERE r.id = %s
        """, param)
    else:
        cur.execute("""
            SELECT r.*, c.name as category_name 
            FROM recipes r 
            LEFT JOIN categories c ON r.category_id = c.id 
            WHERE r.id = ?
        """, param)
    
    recipe = cur.fetchone()
    if not recipe:
        db_close(conn, cur)
        return "Рецепт не найден", 404
    
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            SELECT i.name, i.unit, ri.quantity 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = %s
        """, param)
        ingredients = cur.fetchall()

        cur.execute("""
            SELECT step_number, description 
            FROM recipe_steps 
            WHERE recipe_id = %s 
            ORDER BY step_number
        """, param)
        steps = cur.fetchall()
    else:
        cur.execute("""
            SELECT i.name, i.unit, ri.quantity 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = ?
        """, param)
        ingredients = cur.fetchall()

        cur.execute("""
            SELECT step_number, description 
            FROM recipe_steps 
            WHERE recipe_id = ? 
            ORDER BY step_number
        """, param)
        steps = cur.fetchall()
    
    db_close(conn, cur)
    
    return render_template('recipe_detail.html', recipe=recipe, ingredients=ingredients, 
                           steps=steps, student_info=STUDENT_INFO)

@app.route('/api/recipe/<int:recipe_id>', methods=['GET'])
def api_recipe_detail(recipe_id):
    conn, cur = db_connect()
    param = (recipe_id,)
    query_recipe = """
        SELECT r.*, c.name as category_name 
        FROM recipes r 
        LEFT JOIN categories c ON r.category_id = c.id 
        WHERE r.id = %s
    """ if app.config['DB_TYPE'] == 'postgres' else """
        SELECT r.*, c.name as category_name 
        FROM recipes r 
        LEFT JOIN categories c ON r.category_id = c.id 
        WHERE r.id = ?
    """
    cur.execute(query_recipe, param)
    recipe = cur.fetchone()
    if not recipe:
        db_close(conn, cur)
        return jsonify({'error': 'Recipe not found'}), 404
    
    query_ingredients = """
        SELECT i.name, i.unit, ri.quantity 
        FROM recipe_ingredients ri 
        JOIN ingredients i ON ri.ingredient_id = i.id 
        WHERE ri.recipe_id = %s
    """ if app.config['DB_TYPE'] == 'postgres' else """
        SELECT i.name, i.unit, ri.quantity 
        FROM recipe_ingredients ri 
        JOIN ingredients i ON ri.ingredient_id = i.id 
        WHERE ri.recipe_id = ?
    """
    cur.execute(query_ingredients, param)
    ingredients = cur.fetchall()

    query_steps = """
        SELECT step_number, description 
        FROM recipe_steps 
        WHERE recipe_id = %s 
        ORDER BY step_number
    """ if app.config['DB_TYPE'] == 'postgres' else """
        SELECT step_number, description 
        FROM recipe_steps 
        WHERE recipe_id = ? 
        ORDER BY step_number
    """
    cur.execute(query_steps, param)
    steps = cur.fetchall()
    
    db_close(conn, cur)
    return jsonify({
        'recipe': dict(recipe),
        'ingredients': [dict(i) for i in ingredients],
        'steps': [dict(s) for s in steps]
    })

@app.route('/search', methods=['GET', 'POST'])
def search():
    if not session.get('login'):
        return redirect(url_for('login'))
    
    recipes = []
    keyword = ''
    ingredients_input = ''
    mode = 'any'  # по умолчанию 'any'
    
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip().lower()
        ingredients_input = request.form.get('ingredients', '').strip().lower()
        mode = request.form.get('mode', 'any')  # 'all' или 'any'
        
        if keyword or ingredients_input:
            conn, cur = db_connect()
            params = []
            query = """
                SELECT r.*, c.name as category_name
                FROM recipes r 
                LEFT JOIN categories c ON r.category_id = c.id
            """
            where = []
            if keyword:
                search_term = f'%{keyword}%'
                where.append("LOWER(r.title) LIKE ?") if app.config['DB_TYPE'] == 'sqlite' else where.append("LOWER(r.title) LIKE %s")
                params.append(search_term)
            
            if ingredients_input:
                ingredients_list = [ing.strip() for ing in ingredients_input.split(',') if ing.strip()]
                if ingredients_list:
                    query += """
                        LEFT JOIN recipe_ingredients ri ON r.id = ri.recipe_id
                        LEFT JOIN ingredients i ON ri.ingredient_id = i.id
                    """
                    placeholder = '?' if app.config['DB_TYPE'] == 'sqlite' else '%s'
                    ing_conditions = [f"LOWER(i.name) LIKE {placeholder}" for _ in ingredients_list]
                    ing_params = [f'%{ing}%' for ing in ingredients_list]
                    
                    if mode == 'all':
                        # Для 'all': условия в WHERE (AND) + HAVING для количества
                        where.append("(" + " AND ".join(ing_conditions) + ")")
                        params.extend(ing_params)
                        having_placeholder = '?' if app.config['DB_TYPE'] == 'sqlite' else '%s'
                        query += f" GROUP BY r.id, c.name HAVING COUNT(DISTINCT i.id) = {having_placeholder}"
                        params.append(len(ingredients_list))  # =, а не >= (точное совпадение для "все")
                    else:  # 'any'
                        where.append("(" + " OR ".join(ing_conditions) + ")")
                        params.extend(ing_params)
                        query += " GROUP BY r.id, c.name"
            
            if where:
                query += " WHERE " + " AND ".join(where)
            
            query += " ORDER BY r.title"
            
            cur.execute(query, params)
            recipes = cur.fetchall()
            db_close(conn, cur)
    

    if request.path != '/search':
        return "Not Found", 404
    
    return render_template('search.html',
                           recipes=recipes,
                           keyword=keyword,
                           ingredients=ingredients_input,
                           mode=mode,
                           student_info=STUDENT_INFO)

@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    conn, cur = db_connect()
    cur.execute("""
        SELECT r.*, c.name as category_name 
        FROM recipes r 
        LEFT JOIN categories c ON r.category_id = c.id 
        ORDER BY r.created_at DESC
    """)
    recipes = cur.fetchall()
    
    # Получаем категории для формы добавления/редактирования
    cur.execute("SELECT id, name FROM categories ORDER BY name")
    categories = cur.fetchall()
    db_close(conn, cur)
    return render_template('admin.html', recipes=recipes, categories=categories, student_info=STUDENT_INFO)

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
    ingredients_str = request.form.get('ingredients', '')  # формат: name:quantity unit;name:quantity unit;...
    steps_str = request.form.get('steps', '')  # формат: step1;step2;...
    
    if not all([title, cooking_time, servings, category_id]):
        flash("Заполните обязательные поля")
        return redirect(url_for('admin'))
    
    conn, cur = db_connect()
    param_recipe = (title, description, cooking_time, servings, category_id, image_path)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, param_recipe)
        recipe_id = cur.fetchone()['id']
    else:
        cur.execute("""
            INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, param_recipe)
        recipe_id = cur.lastrowid
    
    # Добавляем ингредиенты
    if ingredients_str:
        ingredients_list = ingredients_str.split(';')
        for ing in ingredients_list:
            parts = ing.split(':')
            if len(parts) == 2:
                name_unit = parts[0].strip().split()
                name = ' '.join(name_unit[:-1]) if len(name_unit) > 1 else name_unit[0]
                unit = name_unit[-1] if len(name_unit) > 1 else ''
                quantity = float(parts[1].strip())
                # Найти или создать ингредиент
                param_ing = (name, unit)
                if app.config['DB_TYPE'] == 'postgres':
                    cur.execute("SELECT id FROM ingredients WHERE name=%s AND unit=%s", param_ing)
                else:
                    cur.execute("SELECT id FROM ingredients WHERE name=? AND unit=?", param_ing)
                ing_id = cur.fetchone()
                if not ing_id:
                    if app.config['DB_TYPE'] == 'postgres':
                        cur.execute("INSERT INTO ingredients (name, unit) VALUES (%s, %s) RETURNING id", param_ing)
                        ing_id = cur.fetchone()['id']
                    else:
                        cur.execute("INSERT INTO ingredients (name, unit) VALUES (?, ?)", param_ing)
                        ing_id = cur.lastrowid
                else:
                    ing_id = ing_id['id']
                # Связать
                param_ri = (recipe_id, ing_id, quantity)
                if app.config['DB_TYPE'] == 'postgres':
                    cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (%s, %s, %s)", param_ri)
                else:
                    cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (?, ?, ?)", param_ri)
    
    # Добавляем шаги
    if steps_str:
        steps_list = steps_str.split(';')
        for idx, step in enumerate(steps_list, 1):
            param_step = (recipe_id, idx, step.strip())
            if app.config['DB_TYPE'] == 'postgres':
                cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (%s, %s, %s)", param_step)
            else:
                cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (?, ?, ?)", param_step)
    
    db_close(conn, cur)
    flash("Рецепт добавлен")
    return redirect(url_for('admin'))

@app.route('/admin/edit_recipe/<int:recipe_id>', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    conn, cur = db_connect()
    
    # Получаем рецепт
    param = (recipe_id,)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM recipes WHERE id = %s", param)
    else:
        cur.execute("SELECT * FROM recipes WHERE id = ?", param)
    recipe = cur.fetchone()
    if not recipe:
        db_close(conn, cur)
        return "Рецепт не найден", 404
    
    # Получаем категории для селекта
    cur.execute("SELECT id, name FROM categories ORDER BY name")
    categories = cur.fetchall()
    
    if request.method == 'GET':
        # Получаем текущие ингредиенты в формате строки
        if app.config['DB_TYPE'] == 'postgres':
            cur.execute("""
                SELECT i.name, i.unit, ri.quantity 
                FROM recipe_ingredients ri 
                JOIN ingredients i ON ri.ingredient_id = i.id 
                WHERE ri.recipe_id = %s
            """, param)
        else:
            cur.execute("""
                SELECT i.name, i.unit, ri.quantity 
                FROM recipe_ingredients ri 
                JOIN ingredients i ON ri.ingredient_id = i.id 
                WHERE ri.recipe_id = ?
            """, param)
        ingredients = cur.fetchall()
        ingredients_str = '; '.join([f"{i['name']} {i['unit'] or ''}:{i['quantity']}".strip() for i in ingredients])
        
        # Получаем шаги
        if app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT description FROM recipe_steps WHERE recipe_id = %s ORDER BY step_number", param)
        else:
            cur.execute("SELECT description FROM recipe_steps WHERE recipe_id = ? ORDER BY step_number", param)
        steps = cur.fetchall()
        steps_str = '; '.join([s['description'] for s in steps])
        
        db_close(conn, cur)
        return render_template('edit_recipe.html', 
                               recipe=recipe, 
                               categories=categories, 
                               ingredients_str=ingredients_str, 
                               steps_str=steps_str, 
                               student_info=STUDENT_INFO)
    
    # POST — сохранение изменений
    title = request.form.get('title')
    description = request.form.get('description')
    cooking_time = request.form.get('cooking_time')
    servings = request.form.get('servings')
    category_id = request.form.get('category_id')
    image_path = request.form.get('image_path', '')
    ingredients_str = request.form.get('ingredients', '')
    steps_str = request.form.get('steps', '')
    
    if not all([title, cooking_time, servings, category_id]):
        flash("Заполните обязательные поля")
        db_close(conn, cur)
        return redirect(url_for('edit_recipe', recipe_id=recipe_id))
    
    # Обновляем рецепт
    update_params = (title, description, cooking_time, servings, category_id, image_path, recipe_id)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            UPDATE recipes 
            SET title=%s, description=%s, cooking_time=%s, servings=%s, category_id=%s, image_path=%s 
            WHERE id=%s
        """, update_params)
    else:
        cur.execute("""
            UPDATE recipes 
            SET title=?, description=?, cooking_time=?, servings=?, category_id=?, image_path=? 
            WHERE id=?
        """, update_params)
    
    # Удаляем старые ингредиенты и шаги
    delete_param = (recipe_id,)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM recipe_ingredients WHERE recipe_id=%s", delete_param)
        cur.execute("DELETE FROM recipe_steps WHERE recipe_id=%s", delete_param)
    else:
        cur.execute("DELETE FROM recipe_ingredients WHERE recipe_id=?", delete_param)
        cur.execute("DELETE FROM recipe_steps WHERE recipe_id=?", delete_param)
    
    # Добавляем новые ингредиенты
    if ingredients_str:
        for item in ingredients_str.split(';'):
            item = item.strip()
            if ':' in item:
                name_part, quantity = item.rsplit(':', 1)
                quantity = quantity.strip()
                name_unit = name_part.strip().split()
                name = ' '.join(name_unit[:-1]) if len(name_unit) > 1 else name_unit[0]
                unit = name_unit[-1] if len(name_unit) > 1 else ''
                try:
                    quantity = float(quantity)
                except:
                    continue
                
                # Находим или создаём ингредиент
                ing_param = (name, unit)
                if app.config['DB_TYPE'] == 'postgres':
                    cur.execute("SELECT id FROM ingredients WHERE name=%s AND unit=%s", ing_param)
                else:
                    cur.execute("SELECT id FROM ingredients WHERE name=? AND unit=?", ing_param)
                row = cur.fetchone()
                if row:
                    ing_id = row['id']
                else:
                    if app.config['DB_TYPE'] == 'postgres':
                        cur.execute("INSERT INTO ingredients (name, unit) VALUES (%s, %s) RETURNING id", ing_param)
                        ing_id = cur.fetchone()['id']
                    else:
                        cur.execute("INSERT INTO ingredients (name, unit) VALUES (?, ?)", ing_param)
                        ing_id = cur.lastrowid
                
                # Связываем
                ri_param = (recipe_id, ing_id, quantity)
                if app.config['DB_TYPE'] == 'postgres':
                    cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (%s, %s, %s)", ri_param)
                else:
                    cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (?, ?, ?)", ri_param)
    
    # Добавляем новые шаги
    if steps_str:
        for idx, desc in enumerate(steps_str.split(';'), 1):
            desc = desc.strip()
            if desc:
                step_param = (recipe_id, idx, desc)
                if app.config['DB_TYPE'] == 'postgres':
                    cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (%s, %s, %s)", step_param)
                else:
                    cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (?, ?, ?)", step_param)
    
    db_close(conn, cur)
    flash("Рецепт успешно обновлён!")
    return redirect(url_for('admin'))

@app.route('/admin/delete_recipe/<int:recipe_id>', methods=['POST'])
def delete_recipe(recipe_id):
    if not session.get('is_admin'):
        return "Доступ запрещён", 403
    
    conn, cur = db_connect()
    param = (recipe_id,)
    if app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM recipes WHERE id=%s;", param)
    else:
        cur.execute("DELETE FROM recipes WHERE id=?;", param)
    db_close(conn, cur)
    flash("Рецепт удалён")
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        conn, cur = db_connect()
        db_type = app.config['DB_TYPE']
        
        # Инициализация таблиц для SQLite
        if db_type == 'sqlite':
            print("Инициализация SQLite...")
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    login TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ingredients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    unit TEXT
                );
                CREATE TABLE IF NOT EXISTS recipes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    cooking_time INTEGER,
                    servings INTEGER,
                    category_id INTEGER,
                    image_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (category_id) REFERENCES categories (id)
                );
                CREATE TABLE IF NOT EXISTS recipe_ingredients (
                    recipe_id INTEGER,
                    ingredient_id INTEGER,
                    quantity REAL,
                    PRIMARY KEY (recipe_id, ingredient_id),
                    FOREIGN KEY (recipe_id) REFERENCES recipes (id) ON DELETE CASCADE,
                    FOREIGN KEY (ingredient_id) REFERENCES ingredients (id)
                );
                CREATE TABLE IF NOT EXISTS recipe_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipe_id INTEGER,
                    step_number INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    FOREIGN KEY (recipe_id) REFERENCES recipes (id) ON DELETE CASCADE
                );
            """)
            conn.commit()
        
        # Создание админа
        param_admin = ('admin',)
        if db_type == 'postgres':
            cur.execute("SELECT login FROM users WHERE login=%s;", param_admin)
        else:
            cur.execute("SELECT login FROM users WHERE login=?;", param_admin)
        
        if not cur.fetchone():
            pwd_hash, salt = hash_password('admin123')
            param_insert = ('admin', pwd_hash, salt, True if db_type == 'postgres' else 1)
            if db_type == 'postgres':
                cur.execute("INSERT INTO users (login, password_hash, salt, is_admin) VALUES (%s, %s, %s, %s);", param_insert)
            else:
                cur.execute("INSERT INTO users (login, password_hash, salt, is_admin) VALUES (?, ?, ?, ?);", param_insert)
            conn.commit()
            print("Админ создан")
        
        # Инициализация категорий (для обеих БД)
        categories = ['Appetizers', 'Main Dishes', 'Desserts', 'Soups', 'Salads', 'Beverages']
        for cat in categories:
            param_cat = (cat,)
            if db_type == 'postgres':
                cur.execute("SELECT id FROM categories WHERE name=%s", param_cat)
            else:
                cur.execute("SELECT id FROM categories WHERE name=?", param_cat)
            if not cur.fetchone():
                if db_type == 'postgres':
                    cur.execute("INSERT INTO categories (name) VALUES (%s)", param_cat)
                else:
                    cur.execute("INSERT INTO categories (name) VALUES (?)", param_cat)
        conn.commit()
        
        # Получаем ID категорий
        cur.execute("SELECT id, name FROM categories")
        cat_dict = {row['name']: row['id'] for row in cur.fetchall()}
        
        # Проверяем, пустая ли таблица recipes (универсально для Postgres и SQLite)
        cur.execute("SELECT COUNT(*) AS cnt FROM recipes")
        row = cur.fetchone()
        count = row['cnt'] if row else 0
        if count == 0:
            print("Добавляем 100 рецептов...")
            # Фейковые рецепты (замените на реальные, если нужно)
            for i in range(100):
                title = f"Recipe {i+1}: Delicious {random.choice(['Chicken', 'Beef', 'Vegan', 'Fish', 'Pasta', 'Cake'])} Dish"
                description = f"A tasty recipe for {title.lower()}."
                cooking_time = random.randint(20, 120)
                servings = random.randint(2, 6)
                category_name = random.choice(categories)
                category_id = cat_dict[category_name]
                image_path = f'https://example.com/image{i+1}.jpg'
                
                param_recipe = (title, description, cooking_time, servings, category_id, image_path)
                if db_type == 'postgres':
                    cur.execute("""
                        INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
                        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                    """, param_recipe)
                    recipe_id = cur.fetchone()['id']
                else:
                    cur.execute("""
                        INSERT INTO recipes (title, description, cooking_time, servings, category_id, image_path)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, param_recipe)
                    recipe_id = cur.lastrowid
                
                # Ингредиенты
                for j in range(random.randint(5, 10)):
                    name = f"Ingredient {j+1} for Recipe {i+1}"
                    unit = random.choice(['g', 'ml', 'pcs'])
                    quantity = round(random.uniform(0.5, 2.0), 2)
                    param_ing = (name, unit)
                    if db_type == 'postgres':
                        cur.execute("SELECT id FROM ingredients WHERE name=%s AND unit=%s", param_ing)
                    else:
                        cur.execute("SELECT id FROM ingredients WHERE name=? AND unit=?", param_ing)
                    ing_row = cur.fetchone()
                    if ing_row:
                        ing_id = ing_row['id']
                    else:
                        if db_type == 'postgres':
                            cur.execute("INSERT INTO ingredients (name, unit) VALUES (%s, %s) RETURNING id", param_ing)
                            ing_id = cur.fetchone()['id']
                        else:
                            cur.execute("INSERT INTO ingredients (name, unit) VALUES (?, ?)", param_ing)
                            ing_id = cur.lastrowid
                    param_ri = (recipe_id, ing_id, quantity)
                    if db_type == 'postgres':
                        cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (%s, %s, %s)", param_ri)
                    else:
                        cur.execute("INSERT INTO recipe_ingredients (recipe_id, ingredient_id, quantity) VALUES (?, ?, ?)", param_ri)
                
                # Шаги
                for k in range(random.randint(3, 6)):
                    description = f"Step {k+1}: Do something with ingredients for Recipe {i+1}."
                    param_step = (recipe_id, k+1, description)
                    if db_type == 'postgres':
                        cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (%s, %s, %s)", param_step)
                    else:
                        cur.execute("INSERT INTO recipe_steps (recipe_id, step_number, description) VALUES (?, ?, ?)", param_step)
            
            conn.commit()
            print("100 рецептов добавлено!")
        
        db_close(conn, cur)
    
    app.run(debug=True)