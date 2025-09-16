import pickle
from flask import Flask, request, jsonify
from sklearn.feature_extraction.text import CountVectorizer
import pandas as pd

# Load the saved model and vectorizer
model = pickle.load(open('model.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))  # Save and load your vectorizer as well

# Create Flask app
app = Flask(__name__)


# Route to handle sentiment analysis
@app.route('/analyze', methods=['POST'])
def analyze_sentiment():
    data = request.json  # Get the JSON data sent from the front-end
    text = data.get('text')  # Extract the text from the JSON

    # Vectorize the input text
    transformed_text = vectorizer.transform([text])

    # Predict using the loaded model
    prediction = model.predict(transformed_text)

    # Return the result as JSON
    sentiment = 'Positive' if prediction == 1 else 'Negative'  # Adjust based on your labels
    return jsonify({'sentiment': sentiment})



if __name__ == '__main__':
    app.run(debug=True)
