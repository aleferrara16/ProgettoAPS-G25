from app import app

if __name__ == '__main__':
    # Esegue il server sulla porta 5000 in locale
    app.run(host='127.0.0.1', port=5000, debug=True)
