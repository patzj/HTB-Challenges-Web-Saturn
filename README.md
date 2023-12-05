# HTB-Challenges-Web-Saturn

## Challenge Description
Saturn corp just launched their new proxy service. According to them, they have made sure their proxy service contains no security issues as they have implemented decent security measures with up to date components.

![159 65 20 166_32699_(Nest Hub)](https://github.com/patzj/HTB-Challenges-Web-Saturn/assets/10325457/0bf135c0-dd9c-4748-bfce-b622c99784d1)

## Reconnaissance
First, I downloaded the files for the challenge and review its source code. Looking at the codes, I can see that the flag is accessible from the `/secret` route but is only accessible by using the loopback address.
```py
@app.route('/secret')
def secret():
    if request.remote_addr == '127.0.0.1':
      # -- snip --
```

The proxy service utilizes a library called safeurl-python: https://github.com/IncludeSecurity/safeurl-python to safeguard against SSRF attacks. While I identified several known vulnerabilities in this library through Snyk: https://security.snyk.io/package/pip/safeurl-python, the deployed version has already been patched to address these issues.
```
Flask==3.0.0
gunicorn==21.2.0
requests==2.31.0
SafeURL-Python==1.3
Werkzeug==3.0.1
```

With my basic SSRF knowledge rendered unusable, I need to be creative in capturing the flag using the knowledge I acquired from software development.

## Scanning
Knowing that the proxy service is protected from SSRF, I need to test for addresses that are blocked and allowed. Long story short, it blocks private IP addresses but allows addresses like https://www.google.com/. So, I checked how safeurl is configured. It turns out the default configurations are pretty strict.

![159 65 20 166_32699_(Nest Hub) (1)](https://github.com/patzj/HTB-Challenges-Web-Saturn/assets/10325457/afa9bb03-936e-4699-91d5-81eea722e0f4)

```py
self._lists = {
        "whitelist": {
            "ip": [],
            "port": ["80", "443", "8080"],
            "domain": [],
            "scheme": ["http", "https"]},
        "blacklist": {
            "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
                "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"],
```

## Method 1 - Redirects *(Failed)*
The proxy service is configured to allow redirects, so it's the first thing that I tried.
```py
try:
    su = safeurl.SafeURL()
    opt = safeurl.Options()
    opt.enableFollowLocation().setFollowLocationLimit(0)
    # -- snip --
```
Knowing that I can't use private addresses, I set up a Flask app on https://www.pythonanywhere.com/ that can redirect requests to the *secret* route.
```
@app.route('/pwn')
def pwn():
    response = Response(None, status=301)
    response.headers.add_header("Location", "http://127.0.0.1:1337/secret")
    return response
```
This was a failure because safeurl continuously validates the redirect URLs. The algorithm can be found [here](https://github.com/IncludeSecurity/safeurl-python/blob/main/safeurl/safeurl.py#L643-L677).

## Method 2 - SSTI *(Failed)*
In the Flask app that I set up on https://www.pythonanywhere.com/, I created routes that would return `7*7` and `{{7*7}}`. I gave up immediately after both didn't work.

## Method 3 - Shortened URL *(Success)*
TODO
![127 0 0 1_1337_(Nest Hub)](https://github.com/patzj/HTB-Challenges-Web-Saturn/assets/10325457/8602fab4-aa77-4486-a2b6-f0466ef9a72c)
