import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = "sqlite:///" + os.path.join(BASE_DIR, "database", "database.db")

SECRET_KEY = "secure_file_sharing_secret_key"