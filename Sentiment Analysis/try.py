import requests

def get_blogs():
    api_key = "318632067304470395b406444efe60b2"  # Replace with your actual API key
    url = "https://newsapi.org/v2/top-headlines"

    # Define query parameters
    params = {
        "sources": "bbc-news",  # You can change this to other sources
        "apiKey": api_key
    }

    # Fetch the data
    response = requests.get(url, params=params)
    data = response.json()

    # Extract articles
    articles = data.get("articles", [])

    # Display blog details
    for i, article in enumerate(articles, start=1):
        print(f"{i}. {article['title']}")  # Title of the blog
        print(f"   {article['description']}")  # Short description
        print(f"   Read more: {article['url']}\n")  # Link to full blog

# Run the function
get_blogs()
