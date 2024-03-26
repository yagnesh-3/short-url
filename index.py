from flask import Flask,render_template,request,redirect
import json
app = Flask(__name__)
urls = {}
@app.route('/',methods=['GET','POST'])
def index():
    final = ""
    short_url = ""
    if request.method == 'POST':
        long = request.form['long_url']
        short = request.form['short_url']
        if(request.form['short_url'] not in urls):
            urls[short] = long
            with open("urls.json","w") as f:
                json.dump(urls,f)
            final = f"link sucessfully created at {request.url_root}{short}"
            short_url = short
        else:
            final = "short url already exist try again "

    par = [final,short_url]

    return render_template('index.html',par = par)


@app.route('/<short_url>')
def redirect_url(short_url):
    long_url = urls.get(short_url)
    return redirect(long_url)

if __name__ == "__main__":
    with open("urls.json","r") as f:
        urls= json.load(f)
    app.run(debug=True, port=5080)