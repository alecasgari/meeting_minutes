# Import necessary parts from Flask library
from flask import Flask, render_template

# 1. Create an instance of the Flask class
#    __name__ tells Flask where to look for resources like templates and static files.
app = Flask(__name__)

# 2. Define a route for the homepage ('/')
#    The @app.route decorator tells Flask that the function below
#    should handle requests to the root URL of the website.
@app.route('/')
def index():
    # 3. This function will be executed when someone visits '/'
    #    It renders (processes and displays) the 'index.html' template.
    #    Flask automatically looks for this file in a folder named 'templates'.
    return render_template('index.html')

# 4. Check if the script is executed directly (not imported)
#    This block allows us to run the development server easily.
if __name__ == '__main__':
    # 5. Start the Flask development server
    #    debug=True enables auto-reloading when code changes and shows detailed error pages.
    #    IMPORTANT: Never run with debug=True in a production environment!
    app.run(debug=True)