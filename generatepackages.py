import http.client
import json

# this generates stdpackages.go from the go github source tree
def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix):]

conn = http.client.HTTPSConnection("api.github.com")
payload = ''
headers = {'User-Agent': 'python'}
conn.request("GET", "/repos/golang/go/git/trees/master?recursive=0", payload, headers)
res = conn.getresponse()
txt = res.read().decode('utf-8')
data = json.loads(txt)


with open('stdpackages.go', 'w') as f:
    f.write("package main\nvar stdPkgs = []string{")

    tree = data['tree']
    for item in tree:
        if item['type'] != 'tree':
            continue
        
        path = item['path']
        if not path.startswith('src'):
            continue
        
        if path == "src":
            continue
        
        path = remove_prefix(path, 'src/')
        f.write("\"{}\",".format(path))
        
    f.write("\"\"}")
       