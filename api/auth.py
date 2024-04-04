import datetime
import requests
import jwt

class GitHubAppAuth:
    def __init__(self, app_id, private_key, installation_id=None):
        self.app_id = app_id
        self.private_key = private_key
        self.installation_id = installation_id

    def generate_jwt(self):
        """
        Generate a JWT token for GitHub App authentication.
        """
        now = int(datetime.datetime.now().timestamp())
        payload = {
            "iat": now - 60,  # Issued at time, 60 seconds ago to account for clock skew
            "exp": now + (10 * 60),  # Expiration time, 10 minutes from now
            "iss": self.app_id
        }
        encoded_jwt = jwt.encode(payload=payload, key=self.private_key, algorithm="RS256")
        return encoded_jwt
    
    
    def get_installation_ids(self):
        """
        List Github App installation IDs.
        """
        jwt_token = self.generate_jwt()
        url = 'https://api.github.com/app/installations'
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.get(url, headers=headers)
        return response.json()


    def get_installation_access_token(self):
        """
        Retrieve an installation access token for the GitHub App.
        """
        if not self.installation_id:
            raise ValueError("Installation ID is not set")

        jwt_token = self.generate_jwt()
        url = f"https://api.github.com/app/installations/{self.installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        return response.json()["token"]