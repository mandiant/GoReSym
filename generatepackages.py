# Python >= 3.6, tested with Python 3.9.5
import requests

# https://docs.github.com/en/rest/reference/git#get-a-tree
API_URL = "https://api.github.com/repos/golang/go/git/trees"
DIR = "src"
OUTPUT_FILE = "stdpackages.go"
VAR_NAME = "standardPackages"


def get_tree(tree_sha):
    url = f"{API_URL}/{tree_sha}"
    print(f"Getting {url}")
    r = requests.get(url)
    r.raise_for_status()
    return r.json()


r = get_tree("master")
for leaf in r["tree"]:
    if leaf["path"] == DIR:
        sha = leaf["sha"]
        break

r = get_tree(f"{sha}?recursive=1")

if r["truncated"]:
    raise RuntimeError("Too many paths, needed to fetch one sub-tree at a time")

# Use list instead of set to keep order
paths = [leaf["path"] for leaf in r["tree"] if leaf["type"] == "tree"]
# paths in the following format: {"path1", "path2", ...}
paths_str = '{"' + '", "'.join(paths) + '"}'

print(f"Writing paths to {OUTPUT_FILE}")
with open(OUTPUT_FILE, "w") as f:
    f.write(f"package main\n\nvar {VAR_NAME} = []string{paths_str}")
