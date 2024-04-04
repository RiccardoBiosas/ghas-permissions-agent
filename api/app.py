import logging
from typing import Dict

from flask import Flask, jsonify, request
import hashlib
import hmac
import requests
import os
from .auth import GitHubAppAuth
from dotenv import load_dotenv
load_dotenv() 

gh_app_pk = os.environ.get('gh_app_pk')
gh_app_inst_id = os.environ.get('gh_app_inst_id')
gh_app_id = os.environ.get('gh_app_id')
gh_app_webhook_secret = os.environ.get('gh_app_webhook_secret')

gh_auth = GitHubAppAuth(gh_app_id, gh_app_pk, gh_app_inst_id)

logger = logging.getLogger("app")

app = Flask("GHAS Permissions Agent")

def extract_github_payload(git_payload):
    """Extracts and returns necessary information from GitHub webhook payload."""
    extracted_data = {
        'action': git_payload.get('action'),
        'alert_number': git_payload.get('alert', {}).get('number'),
        'alert_created_at': git_payload.get('alert', {}).get('created_at'),
        'alert_updated_at': git_payload.get('alert', {}).get('updated_at'),
        'alert_url': git_payload.get('alert', {}).get('url'),
        'alert_html_url': git_payload.get('alert', {}).get('html_url'),
        'alert_state': git_payload.get('alert', {}).get('state'),
        'alert_dismissed_at': git_payload.get('alert', {}).get('dismissed_at'),
        'alert_dismissed_reason': git_payload.get('alert', {}).get('dismissed_reason'),
        'alert_rule': git_payload.get('alert', {}).get('rule', {}),
        'repository': git_payload.get('repository', {}),
        'organization': git_payload.get('organization', {}),
        'sender': git_payload.get('sender', {})
    }
    return extracted_data

@app.route("/github", methods=["POST"])
def github():
    if gh_app_webhook_secret:
        signature_header = request.headers.get('X-Hub-Signature')
        sha_name, github_signature = signature_header.split('=')
        if sha_name != 'sha1':
            print('ERROR: X-Hub-Signature in payload headers was not sha1=****')
            return False
          
        body = request.get_data()
        local_signature = hmac.new(gh_app_webhook_secret.encode('utf-8'), msg=body, digestmod=hashlib.sha1)
        is_wh_sig_matching = hmac.compare_digest(local_signature.hexdigest(), github_signature)
        print(f"Is webhook secret's signature matching? ${is_wh_sig_matching}")
   
    git_payload = extract_github_payload(request.json)


    print(f"detected git webhook action: {git_payload['action']}")
    if git_payload['action'] == 'closed_by_user':
        print(f""" #########
            {git_payload}
        ######## """)
        # TODO: fetch the authorized users programmatically from the Github API
        authorized_handles = os.environ.get('authorized_handles', [])
        print("authorized_handles: " + str(authorized_handles))
        dismisser_github_handle = git_payload['sender'].get('login')
        print(f"github username who dismissed GHAS alert: {dismisser_github_handle}")
        if dismisser_github_handle not in authorized_handles:
            token = gh_auth.get_installation_access_token()
            headers = {
                    'Accept': 'application/vnd.github+json',
                    'Authorization': f'token {token}', 
                    'X-GitHub-Api-Version': '2022-11-28'
            }
            print(f"github username {dismisser_github_handle} is not authorized to dismiss GHAS alert {git_payload['alert_url']}")
            response = requests.patch(git_payload['alert_url'], headers=headers, json={"state": "open"})
            print(f"GHAS alert {response.json()['url']} reopened")
            return jsonify({"body": f"GHAS alert {git_payload['alert_url']} was ignored by unauthorized user: {dismisser_github_handle}. GHAS alert {response.json()['url']} reopened"}) 
        else:
            print(f"authorized github username {dismisser_github_handle} dismissed a GHAS alert")
            return jsonify({"body": f"GHAS alert {git_payload['alert_url']} was ignored by authorized user: {dismisser_github_handle}. No unauthorized action detected."}) 
    
    return jsonify({"body": f"Action was not `closed_by_user`: detected action was {git_payload['action']}: no changes have been applied."})




def run(config: Dict, debug: bool = False):
    app.config.update(**config)

    app.run("0.0.0.0", debug=debug, port=8000)
