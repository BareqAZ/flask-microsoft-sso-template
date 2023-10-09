# Flask Microsoft SSO Template

This is a basic Flask template to help kick-start the development of your next Flask project without having to write the entire authentication code yourself. <br>
This template supports local database users, Azure active directory users via Microsoft Graph API, and API authentication for both local and Azure users.


## Key Features

- **Local Users Support:** Utilizes SQLite for local user management.
- **Azure Active Directory Integration:** Integrates Microsoft SSO by using the Microsoft Graph API.
- **API Access Management:** Basic API access management for all users.
- **Encryption:** The project utilizes a custom encryption library that utilizes the Flask secret key to encrypt and decrypt sensitive database information.
- **Log Management:** Basic logging and error handling to syslog.
- **Gunicorn:** Gunicorn production ready server integrated.

## Demo

Follow these steps to set up a demo environment:

1. **Setup Azure AD App:** <br>
Create a new Azure AD app by referring to [this guide](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/walkthrough-register-app-azure-active-directory).

2. **Configure Azure App Credentials:** <br>
Configure the Azure app credentials in the Flask app by copying the default settings `./src/settings.toml.default` file to `./src/settings.toml` and configuring the new settings file with the Azure app credentials.

3. **Setup Python Virtual Environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip3 install -r requirements.txt
   ```

4. **Run the Debug server:**
   ```bash
   ./run_debug_server.sh
   ```

5. **Use the demo:** <br>
  Access the web portal (default localhost:5000) to test UI logins.<br>
  After logging in, obtain the user's API token, which you can use for testing the API routes found in `./src/app/api/routes.py.`
  
## Development Workflow

1. Run the debug server:
`./run_debug_server.sh`

2. Make code changes and test them in real-time.

3. You probably want to create and run some tests here.

4. Run linters for code quality checks:
`./run_linters.sh`

5. Done!

## Project Structure
```
src
├── app
│   ├── api         # Contains all the API routes
│   │   
│   ├── auth        # Contains authentication routes, SSO modules, and helper functions
│   │   
│   ├── static      # Static files such as images, icons, and JavaScript
│   │
│   ├── templates   # Flask templates
│   │
│   └── user        # User-accessible routes
│
├── settings.toml   # Contains all configurable settings and credentials
│
└── bin             # Contains executables for starting both the debug and production servers
```
