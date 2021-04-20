#!/usr/bin/env python3

import base64
import json
import pprint
import sys

try:
    import requests
except:
    print("please install requests (pip install requests)")
    sys.exit(1)

def get_perms(url, apikey, index):
    # enumerate the permissions for a given API key/index combination

    payload = {
        "index": [
            {
                "names": [
                    index
                ],
                # these are all of the possible permissions for an ES index
                "privileges": [
                    "all",
                    "auto_configure",
                    "create",
                    "create_doc",
                    "create_index",
                    "delete",
                    "delete_index",
                    "index",
                    "maintenance",
                    "manage",
                    "manage_follow_index",
                    "manage_ilm",
                    "manage_leader_index",
                    "monitor",
                    "read",
                    "read_cross_cluster",
                    "view_index_metadata",
                    "write"
                ]
            }
        ]
    }

    headers = {
        "Authorization": f"ApiKey {base64.b64encode(apikey.encode()).decode()}",
        "Content-Type": "application/json; charset=UTF-8"
    }

    r = requests.get(url + "/_security/user/_has_privileges", headers=headers, data=json.dumps(payload), verify=False)

    resp = r.json()

    print(f"The API key {apikey} has the following permissions on index {index}:")
    for k, v in resp["index"][index].items():
        if v:
            print(f"\t{k}")

    print("")

    if resp["index"][index]["delete"]:
        print("The API key has delete permissions, VULNERABLE")
    else:
        print("The API key doesn't have delete permissions, NOT VULNERABLE")

def main(argv):
    if len(argv) != 4:
        print(f"usage: {argv[0]} [elasticsearch url] [api key, non-b64] [index]")
        print(f"the index should be security sensitive, e.g. .ds-logs-windows.security-default-xxxxxx")
        return 1

    get_perms(argv[1].rstrip("/"), argv[2], argv[3])

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))