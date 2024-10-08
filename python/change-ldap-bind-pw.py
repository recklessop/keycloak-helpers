import requests
import logging
import getpass
import json
import sys
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REALM = "zerto"  # The realm is always "zerto"

def get_access_token(base_url, username, admin_password):
    """
    Authenticate with Keycloak and return an access token.
    """
    url = f"{base_url}/realms/{REALM}/protocol/openid-connect/token"
    data = {
        'client_id': 'admin-cli',
        'username': username,
        'password': admin_password,
        'grant_type': 'password'
    }
    
    response = requests.post(url, data=data, verify=False)  # Disable SSL verification
    
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        logging.error(f"Failed to authenticate: {response.text}")
        sys.exit(1)

def get_ldap_component(base_url, access_token):
    """
    Fetch all user federation providers and find the LDAP provider.
    """
    url = f"{base_url}/admin/realms/{REALM}/components"
    params = {'type': 'org.keycloak.storage.UserStorageProvider'}
    
    headers = {
        'Authorization': f"Bearer {access_token}"
    }
    
    response = requests.get(url, headers=headers, params=params, verify=False)  # Disable SSL verification
    
    if response.status_code == 200:
        components = response.json()
        for component in components:
            if component['providerId'] == 'ldap' and component['parentId'].lower() == 'zerto':
                logging.info(f"Found LDAP provider. {component}")
                return component
        logging.error("LDAP provider not found.")
        sys.exit(1)
    else:
        logging.error(f"Failed to fetch user federation providers: {response.text}")
        sys.exit(1)

def update_ldap_password(base_url, component, access_token, new_password):
    """
    Update the LDAP bind password for the specified component.
    """
    url = f"{base_url}/admin/realms/{REALM}/components/{component['id']}"
    
    # Update the password in the config
    component['config']['bindCredential'] = [new_password]
    
    headers = {
        'Authorization': f"Bearer {access_token}",
        'Content-Type': 'application/json'
    }
    
    response = requests.put(url, headers=headers, data=json.dumps(component), verify=False)  # Disable SSL verification
    
    if response.status_code == 204:
        logging.info("New password accepted.")
    else:
        logging.error(f"Failed to update password: {response.text}")

def main(base_url, username):
    # Ask for Keycloak admin password
    admin_password = getpass.getpass(prompt="Enter Keycloak admin password: ")

    # Get access token
    access_token = get_access_token(base_url, username, admin_password)
    logging.info("Connected to Keycloak.")

    # Get LDAP component
    ldap_component = get_ldap_component(base_url, access_token)
    
    # Ask for the new LDAP bind password
    new_password = getpass.getpass(prompt="Enter new LDAP bind password: ")

    # Update LDAP bind password
    update_ldap_password(base_url, ldap_component, access_token, new_password)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python update_ldap_password.py <https://KeycloakServerIP/auth> <Keycloak Username>")
        sys.exit(1)

    base_url = sys.argv[1]
    username = sys.argv[2]
    
    main(base_url, username)
