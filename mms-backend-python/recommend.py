from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import numpy as np
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/recommend": {"origins": "http://localhost:8080"}})

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'Pass@123'),
        database=os.getenv('DB_NAME', 'mms_db')
    )

def train_recommendation_model():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT user_email, screening_id, seats_booked FROM bookings WHERE payment_status = "completed"')
    bookings = cursor.fetchall()
    cursor.execute('SELECT screening_id, movie_id FROM screenings')
    screenings = cursor.fetchall()
    cursor.execute('SELECT movie_id, genre, director, actors, price, language FROM movies')
    movies = cursor.fetchall()
    cursor.close()
    conn.close()

    screening_to_movie = {s['screening_id']: s['movie_id'] for s in screenings}
    movie_features = {m['movie_id']: m for m in movies}

    data = []
    for booking in bookings:
        screening_id = booking['screening_id']
        movie_id = screening_to_movie.get(screening_id)
        if not movie_id or movie_id not in movie_features:
            continue
        movie = movie_features[movie_id]
        data.append({
            'user': booking['user_email'],
            'movie_id': movie_id,
            'genre': movie['genre'],
            'director': movie['director'],
            'actors': movie['actors'],
            'price': movie['price'],
            'language': movie['language'],
            'booked': 1
        })

    if not data:
        return None, None, None

    df = pd.DataFrame(data)
    df = pd.get_dummies(df, columns=['genre', 'director', 'actors', 'language'])
    X = df.drop(['user', 'movie_id', 'booked'], axis=1)
    y = df['booked']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = LogisticRegression()
    model.fit(X_scaled, y)
    
    return model, scaler, X.columns

@app.route('/recommend', methods=['GET'])
def recommend():
    user = request.args.get('user')
    if not user:
        return jsonify({'message': 'User email required'}), 400

    model, scaler, feature_columns = train_recommendation_model()
    if not model:
        return jsonify({'message': 'No booking data available'}), 404

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT movie_id, genre, director, actors, price, language, title FROM movies WHERE coming_soon = FALSE')
    movies = cursor.fetchall()
    cursor.close()
    conn.close()

    recommendations = []
    for movie in movies:
        movie_data = pd.DataFrame([{
            'genre': movie['genre'],
            'director': movie['director'],
            'actors': movie['actors'],
            'price': movie['price'],
            'language': movie['language']
        }])
        movie_data = pd.get_dummies(movie_data)
        movie_data = movie_data.reindex(columns=feature_columns, fill_value=0)
        score = model.predict_proba(scaler.transform(movie_data))[0][1]
        recommendations.append({
            'id': movie['movie_id'],
            'title': movie['title'],
            'genre': movie['genre'],
            'score': score
        })

    recommendations = sorted(recommendations, key=lambda x: x['score'], reverse=True)[:3]
    return jsonify(recommendations)

if __name__ == '__main__':
    app.run(port=5000, debug=True)