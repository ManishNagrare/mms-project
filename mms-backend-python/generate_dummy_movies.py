import mysql.connector
from faker import Faker
import random
from datetime import datetime, timedelta

# Faker ऑब्जेक्ट बनाएँ
fake = Faker()

# डेटाबेस कनेक्शन
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Pass@123",
        database="mms_db"
    )

# डमी मूवी डेटा जेनरेट करें
def generate_dummy_movie():
    genres = ["Action", "Drama", "Comedy", "Thriller", "Sci-Fi", "Romance", "Horror", "Adventure", "Fantasy", "Animation"]
    languages = ["English", "Hindi", "Spanish", "French", "German", "Tamil", "Telugu"]
    formats = ["2D", "3D", "IMAX"]
    cinemas = ["Cinema 1", "Cinema 2", "Cinema 3", "Cinema 4"]

    # मूवी टाइटल जेनरेट करें (उदाहरण: "The Great Adventure")
    title = fake.sentence(nb_words=3).replace(".", "").capitalize() + " " + str(random.randint(1, 5))

    # रैंडम शो टाइम (आज से 1-30 दिन बाद)
    show_time = datetime.now() + timedelta(days=random.randint(1, 30))

    return {
        "title": title,
        "genre": random.choice(genres),
        "duration": random.randint(90, 180),  # 90 से 180 मिनट
        "rating": round(random.uniform(1, 10), 1),  # 1 से 10 के बीच रेटिंग
        "director": fake.name(),
        "actors": ", ".join([fake.name() for _ in range(3)]),  # 3 एक्टर्स
        "price": round(random.uniform(100, 500), 2),  # 100 से 500 के बीच प्राइस
        "language": random.choice(languages),
        "subtitle_language": random.choice(languages),
        "show_time": show_time.strftime('%Y-%m-%d %H:%M:%S'),
        "format": random.choice(formats),
        "cinema": random.choice(cinemas),
        "coming_soon": random.choice([True, False])
    }

# डेटाबेस में 1000 मूवीज़ डालें
def insert_dummy_movies(count=1000):
    conn = get_db_connection()
    cursor = conn.cursor()

    for _ in range(count):
        movie = generate_dummy_movie()
        query = """
        INSERT INTO movies (title, genre, duration, rating, director, actors, price, language, subtitle_language, show_time, format, cinema, coming_soon)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            movie["title"],
            movie["genre"],
            movie["duration"],
            movie["rating"],
            movie["director"],
            movie["actors"],
            movie["price"],
            movie["language"],
            movie["subtitle_language"],
            movie["show_time"],
            movie["format"],
            movie["cinema"],
            movie["coming_soon"]
        )
        cursor.execute(query, values)

    conn.commit()
    cursor.close()
    conn.close()
    print(f"Successfully inserted {count} dummy movies into the database.")

# स्क्रिप्ट चलाएँ
if __name__ == "__main__":
    insert_dummy_movies(1000)