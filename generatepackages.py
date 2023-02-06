# Python >= 3.6, tested with Python 3.9.5
import requests

auth_user = ""
auth_token = ""

# https://docs.github.com/en/rest/reference/git#get-a-tree
TREE_API_URL = "https://api.github.com/repos/golang/go/git/trees"
TAG_API_URL = "https://api.github.com/repos/golang/go/git/refs/tags"
DIR = "src"
OUTPUT_FILE = "stdpackages.go"
VAR_NAME = "standardPackages"

def get_tree(tree_sha):
    url = f"{TREE_API_URL}/{tree_sha}"
    print(f"Getting {url}")
    r = requests.get(url, auth=(auth_user,auth_token))
    r.raise_for_status()
    return r.json()

def remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix):]

def get_go_tags():
    url = TAG_API_URL
    print(f"Fetching version tags {url}")
    r = requests.get(url, auth=(auth_user,auth_token))
    r.raise_for_status()
    j = r.json()
    
    version_tags = ["master"]
    for obj in j:
        tag = remove_prefix(obj["ref"], "refs/tags/")
        if "weekly" in tag:
            continue
        
        version_tags.append(tag)
    return version_tags

def filter_path(path):
    f = remove_prefix(path, "cmd/vendor/")
    return f
    
# enumerates all go version trees by tag (package paths have been re-ordered over time, so we must get all of them)
paths = []
for tag in get_go_tags():
    r = get_tree(tag)
    for leaf in r["tree"]:
        if leaf["path"] == DIR:
            sha = leaf["sha"]
            break
    
    r = get_tree(f"{sha}?recursive=1")
    
    if r["truncated"]:
        raise RuntimeError("Too many paths, needed to fetch one sub-tree at a time")
    
    # enumerates the file tree via directory
    # Use list instead of set to keep order
    new_paths = [filter_path(leaf["path"]) for leaf in r["tree"] if leaf["type"] == "tree"]
    paths.extend(x for x in new_paths if x not in paths)
    
print(f"Writing paths to {OUTPUT_FILE}")

# paths in the following format: {"path1", "path2", ...}
paths_str = '{"' + '", "'.join(paths) + '"}'
with open(OUTPUT_FILE, "w") as f:
    f.write(f"package main\n\nvar {VAR_NAME} = []string{paths_str}")
