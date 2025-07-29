from flask import Flask, render_template, request, redirect, session, flash, g
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'algoarena'

mysql = MySQL(app)

# ---------- ROUTES ----------

@app.route('/')
def home():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cursor.fetchone()
    if user and check_password_hash(user['password'], password):
        session['loggedin'] = True
        session['username'] = user['username']
        session['user_id'] = user['id']
        session['is_admin'] = user.get('is_admin', False)
        return redirect('/dashboard')
    else:
        flash('Incorrect credentials')
        return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s OR username = %s', (email, username))
        existing = cursor.fetchone()
        if existing:
            flash('User already exists')
            return redirect('/register')

        cursor.execute('INSERT INTO users (username, email, password, xp, level, rank) VALUES (%s, %s, %s, %s, %s, %s)',
                       (username, email, hashed_pw, 0, 1, 100))
        mysql.connection.commit()
        flash('Registered successfully. Please login.')
        return redirect('/')
    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT xp, level, rank FROM users WHERE username = %s', (session['username'],))
        data = cursor.fetchone()

        current_xp = data['xp']
        current_level = data['level']
        next_level_xp = 500 + current_level * 200

        return render_template('index.html', name=session['username'],
                               xp=current_xp, level=current_level,
                               next_xp=next_level_xp, rank=data['rank'])
    return redirect('/')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect('/')


@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (session['username'],))
        user = cursor.fetchone()
        return render_template('profile.html', user=user)
    return redirect('/')


@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'loggedin' in session:
        new_username = request.form['username']
        email = request.form['email']
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET username = %s, email = %s WHERE username = %s',
                       (new_username, email, session['username']))
        mysql.connection.commit()
        session['username'] = new_username
        flash('Profile updated')
        return redirect('/profile')
    return redirect('/')


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor()
        cursor.execute('DELETE FROM users WHERE username = %s', (session['username'],))
        mysql.connection.commit()
        session.clear()
        flash('Account deleted')
        return redirect('/')
    return redirect('/')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        hashed_pw = generate_password_hash(new_password)

        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_pw, email))
        mysql.connection.commit()
        flash('Password reset')
        return redirect('/')
    return render_template('reset_password.html')


@app.route('/settings')
def settings():
    if 'loggedin' in session:
        return render_template('settings.html')
    return redirect('/')


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'loggedin' in session:
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (session['username'],))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], current_password):
            hashed_pw = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = %s WHERE username = %s',
                           (hashed_pw, session['username']))
            mysql.connection.commit()
            flash('Password changed')
        else:
            flash('Incorrect current password')
        return redirect('/settings')
    return redirect('/')


@app.route('/admin')
def admin():
    if 'loggedin' in session and session.get('is_admin'):
        return render_template('admin.html')
    return redirect('/')


@app.route('/admin/users')
def admin_users():
    if 'loggedin' in session and session.get('is_admin'):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        return render_template('admin_users.html', users=users)
    return redirect('/')


@app.route('/leaderboard')
def leaderboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT username, xp FROM users ORDER BY xp DESC LIMIT 10')
        top_users = cursor.fetchall()
        return render_template('leaderboard.html', top_users=top_users)
    return redirect('/')


@app.route('/gain_xp', methods=['POST'])
def gain_xp():
    if 'loggedin' in session:
        xp_earned = int(request.form['xp'])
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET xp = xp + %s WHERE id = %s', (xp_earned, user_id))

        # Update weekly leaderboard
        week_start = (date.today() - timedelta(days=date.today().weekday()))
        cursor.execute("""
            INSERT INTO leaderboard (user_id, week_start, xp)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE xp = xp + VALUES(xp)
        """, (user_id, week_start, xp_earned))

        mysql.connection.commit()
        flash(f"You gained {xp_earned} XP!")
        return redirect('/dashboard')
    return redirect('/')


# ---------- QUIZ ----------

@app.route('/quiz')
def quiz():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM quizzes ORDER BY RAND() LIMIT 5")
        questions = cursor.fetchall()
        return render_template('quiz.html', questions=questions)
    return redirect('/')


@app.route('/submit_quiz', methods=['POST'])
def submit_quiz():
    if 'loggedin' in session:
        answers = request.form.to_dict()
        score = 0
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        for q_id, user_ans in answers.items():
            cursor.execute("SELECT correct_option FROM quizzes WHERE id = %s", (q_id,))
            correct = cursor.fetchone()
            if correct and correct['correct_option'].strip().lower() == user_ans.strip().lower():
                score += 10

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET xp = xp + %s WHERE id = %s", (score, session['user_id']))
        mysql.connection.commit()
        flash(f"You scored {score} XP!")
        return redirect('/dashboard')
    return redirect('/')


# ---------- FEEDBACK ----------

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if 'loggedin' in session:
        message = request.form['feedback']
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO feedback (user_id, message) VALUES (%s, %s)", (session['user_id'], message))
        mysql.connection.commit()
        flash("Feedback submitted!")
        return redirect('/dashboard')
    return redirect('/')


@app.route('/admin/feedback')
def view_feedback():
    if 'loggedin' in session and session.get('is_admin'):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT f.message, f.submitted_at, u.username
            FROM feedback f
            JOIN users u ON f.user_id = u.id
            ORDER BY f.submitted_at DESC
        """)
        all_feedback = cursor.fetchall()
        return render_template('admin_feedback.html', feedback=all_feedback)
    return redirect('/')


# ---------- CONTEXT & ERRORS ----------

@app.before_request
def before_request():
    g.username = session['username'] if 'loggedin' in session else None


@app.context_processor
def inject_user():
    return {'username': g.username}


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# ---------- MAIN ----------

if __name__ == '__main__':
    app.run(debug=True)
