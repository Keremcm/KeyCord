import json
import os
from flask import current_app

class HelpService:
    _data = None

    @classmethod
    def load_data(cls):
        """Loads the help content from JSON file if not already loaded."""
        if cls._data is None:
            file_path = os.path.join(current_app.root_path, 'data', 'help_content.json')
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    cls._data = json.load(f)
            except FileNotFoundError:
                cls._data = {"categories": [], "articles": []}
            except Exception as e:
                print(f"Error loading help content: {e}")
                cls._data = {"categories": [], "articles": []}
        return cls._data

    @classmethod
    def get_categories(cls):
        """Returns the list of categories."""
        data = cls.load_data()
        return data.get('categories', [])

    @classmethod
    def get_articles_by_category(cls, category_id):
        """Returns articles belonging to a specific category."""
        data = cls.load_data()
        all_articles = data.get('articles', [])
        return [a for a in all_articles if a.get('category_id') == category_id]

    @classmethod
    def get_article(cls, slug):
        """Finds a specific article by its slug."""
        data = cls.load_data()
        for article in data.get('articles', []):
            if article.get('slug') == slug:
                return article
        return None

    @classmethod
    def search_articles(cls, query):
        """
        Performs a basic fuzzy search on articles.
        Checks title, content, and keywords.
        """
        if not query:
            return []
        
        query = query.lower().strip()
        data = cls.load_data()
        results = []

        for article in data.get('articles', []):
            score = 0
            # Title match (High weight)
            if query in article.get('title', '').lower():
                score += 10
            
            # Keyword match (Medium weight)
            for kw in article.get('keywords', []):
                if query in kw.lower():
                    score += 5
            
            # Content match (Low weight)
            if query in article.get('content', '').lower():
                score += 1
            
            if score > 0:
                results.append({
                    "article": article,
                    "score": score
                })
        
        # Sort by relevance
        results.sort(key=lambda x: x['score'], reverse=True)
        return [r['article'] for r in results]
