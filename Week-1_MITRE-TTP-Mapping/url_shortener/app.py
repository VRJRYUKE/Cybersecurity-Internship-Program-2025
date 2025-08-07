from flask import Flask, request, redirect, render_template
import sqlite3
import string

app = Flask(__name__)
BASE62 = string.digits + string.ascii_letters

# Function to convert number to base62 string
def encode_base62(num):
    base62 = ""
    while num:
        num, rem = divmod(num, 62)
        base62 = BASE62[rem] + base62
    return base62 or "0"

# Create the database and table if not exist
def init_db():
    with sqlite3.connect("shortener.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                long_url TEXT NOT NULL,
                short_code TEXT UNIQUE
            );
        ''')

# Route for main page: show form and shortened URL
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        long_url = request.form['long_url']
        with sqlite3.connect("shortener.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO urls (long_url) VALUES (?)", (long_url,))
            id = cursor.lastrowid
            short_code = encode_base62(id)
            cursor.execute("UPDATE urls SET short_code=? WHERE id=?", (short_code, id))
            conn.commit()
            short_url = request.host_url + short_code
        return render_template('index.html', short_url=short_url)
    return render_template('index.html')

# Route to redirect short code to long URL
@app.route('/<short_code>')
def redirect_to_url(short_code):
    with sqlite3.connect("shortener.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT long_url FROM urls WHERE short_code=?", (short_code,))
        result = cursor.fetchone()
        if result:
            return redirect(result[0])
        else:
            return "URL not found", 404

# Run the app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
