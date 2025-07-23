from api import create_app

app = create_app()

if __name__ == '__main__':
    # Using debug=True is great for development
    app.run(host='0.0.0.0', port=5001, debug=True)
