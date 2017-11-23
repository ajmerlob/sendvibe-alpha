source env/bin/activate
git add application.py
git commit -m "$1"
eb deploy
