from flask import Flask,render_template,request,redirect
import json
app = Flask(__name__)
urls = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    final = ""
    short_url = ""
    if request.method == 'POST':
        long = request.form['long_url']
        short = request.form['short_url']

        # Ensure long URLs start with "http://" or "https://"
        if not long.startswith(('http://', 'https://')):
            long = 'https://' + long  # Default to HTTPS

        if short not in urls:
            urls[short] = long
            with open("urls.json", "w") as f:
                json.dump(urls, f)
            final = f"Link successfully created at {request.url_root}{short}"
            short_url = short
        else:
            final = "Short URL already exists, try another."

    par = [final, short_url]
    return render_template('index.html', par=par)


@app.route('/<short_url>')
def redirect_url(short_url):
    long_url = urls.get(short_url)
    if long_url:
        return redirect(long_url)
    return "Short URL not found", 404

if __name__ == "__main__":
    with open("urls.json","r") as f:
        urls= json.load(f)
    app.run(host="0.0.0.0", port=5080)

