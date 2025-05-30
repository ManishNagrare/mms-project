from flask import Flask, jsonify
from flask_cors import CORS
import mysql.connector
import os

app = Flask(__name__)
CORS(app)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DATABASE_HOST"),
        user=os.getenv("DATABASE_USER"),
        password=os.getenv("DATABASE_PASSWORD"),
        database=os.getenv("DATABASE_NAME"),
        ssl_ca="/etc/ssl/certs/ca-certificates.crt",
        ssl_verify_cert=True
    )

@app.route('/movies', methods=['GET'])
def get_movies():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM movies")
    movies = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(movies)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
