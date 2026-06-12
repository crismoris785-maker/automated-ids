from pymongo import MongoClient
import os

def get_db_connection():
    # Use environment variable for URI or default to local
    mongo_uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    client = MongoClient(mongo_uri)
    db = client['incident_response_db']
    return db
