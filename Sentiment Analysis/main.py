import sys
import pickle
import requests
import random
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from sklearn.feature_extraction.text import CountVectorizer
from threading import Thread

# Load Sentiment Analysis Model
model = pickle.load(open('logistic_regression_model.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

# Flask App
flask_app = Flask(__name__)
CORS(flask_app)

# Database Connection
def get_db_connection():
    conn = sqlite3.connect('sentiment_analysis.db')
    conn.row_factory = sqlite3.Row
    return conn

# Fetch Random News with More Details
def get_random_news():
    api_key = "318632067304470395b406444efe60b2"  # Replace with your actual API key
    url = "https://newsapi.org/v2/top-headlines"

    params = {
        "sources": "bbc-news",
        "apiKey": api_key
    }

    response = requests.get(url, params=params)
    data = response.json()

    articles = data.get("articles", [])

    if articles:
        article = random.choice(articles)  # Pick a random article
        return {
            "title": article.get("title", "No Title Available"),
            "author": article.get("author", "Unknown"),
            "publishedAt": article.get("publishedAt", "Unknown Date"),
            "content": article.get("content", "No additional content available."),
            "description": article.get("description", "No description available."),
            "url": article.get("url", "#")
        }
    else:
        return {"error": "No articles found."}

# API Endpoint to Fetch Previous Sentiment Entries
@flask_app.route('/previous_entries', methods=['GET'])
def get_previous_entries():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT text, sentiment, timestamp FROM sentiment_entries ORDER BY id DESC LIMIT 10")
    entries = cursor.fetchall()
    conn.close()

    if not entries:
        return jsonify({'error': 'No previous entries found.'}), 404

    return jsonify([
        {'text': row['text'], 'sentiment': row['sentiment'], 'timestamp': row['timestamp']}
        for row in entries
    ])

# API Endpoint to Fetch Random News
@flask_app.route('/get_blog', methods=['GET'])
def fetch_blog():
    blog = get_random_news()
    return jsonify(blog)

# API Endpoint for Sentiment Analysis
@flask_app.route('/analyze', methods=['POST'])
def analyze_sentiment():
    data = request.get_json()
    text = data.get("text", "")

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    # Transform text using vectorizer and predict sentiment
    transformed_text = vectorizer.transform([text])
    prediction = model.predict(transformed_text)[0]

    sentiments = ["Sadness", "Neutral", "Love", "Anger", "Fear", "Surprise"]
    sentiment = sentiments[int(prediction)]

    # Store result in database with timestamp
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Correct format
    cursor.execute('INSERT INTO sentiment_entries (text, sentiment, timestamp) VALUES (?, ?, ?)', (text, sentiment, timestamp))
    conn.commit()
    conn.close()

    return jsonify({'sentiment': sentiment})

# PyQt5 GUI Window to Load Web App
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentiment Analysis Blog")
        self.resize(1000, 800)
        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("file:///C:/Users/patil/PycharmProjects/Sentiment Analysis/logo.html"))
        self.setCentralWidget(self.browser)

# Function to Run Flask Server
def run_flask_app():
    flask_app.run(debug=False, port=5000)

# Run Both Flask & PyQt5
if __name__ == '__main__':
    flask_thread = Thread(target=run_flask_app)
    flask_thread.start()

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())