# Epic FHIR Lab Report Service

A Python application that connects to the Epic Sandbox FHIR Server, retrieves lab reports for patients, and sends them via email every 24 hours.

## Features

- **JWT-based Backend App Authentication**: Uses RS384 signed JWTs for secure Epic FHIR API authentication
- **Lab Report Retrieval**: Fetches laboratory observations and vital signs from Epic FHIR R4 API
- **Normal & Abnormal Classification**: Automatically classifies results based on interpretation codes
- **HTML Email Reports**: Generates formatted HTML and plain text email reports
- **24-Hour Scheduling**: Automatically runs every 24 hours with the `schedule` library
- **Configurable SMTP**: Works with Ethereal Email or any SMTP provider

## Prerequisites

1. **Python 3.8+** installed on your system
2. **Epic App Registration**: A registered backend application on Epic's developer portal
3. **RSA Key Pair**: Private key for JWT signing (public key registered with Epic)
4. **Ethereal Email Account**: For testing email delivery (or another SMTP server)

## Project Structure

```
epic_lab_reports/
├── epic_fhir_client.py    # Main application code
├── config.json            # Your configuration (create from config.example.json)
├── config.example.json    # Example configuration template
├── privatekey.pem         # Your RSA private key (do not commit!)
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Installation

### 1. Clone or copy the project files

```bash
mkdir epic_lab_reports
cd epic_lab_reports
# Copy all project files here
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the application

Copy the example configuration:

```bash
cp config.example.json config.json
```

Edit `config.json` with your settings:

```json
{
    "epic": {
        "client_id": "YOUR_EPIC_CLIENT_ID",
        "private_key_path": "path/to/your/privatekey.pem",
        "token_url": "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token",
        "fhir_base_url": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
    },
    "email": {
        "smtp_host": "smtp.ethereal.email",
        "smtp_port": 587,
        "smtp_user": "your-ethereal-user@ethereal.email",
        "smtp_password": "your-ethereal-password",
        "from_email": "labreports@yourdomain.com",
        "to_email": "recipient@example.com"
    }
}
```

### 5. Add your private key

Copy your RSA private key to the project directory:

```bash
# From your key location
cp "C:\Users\kr58643\Documents\fhir-bootcamp\backend-app-epic\privatekey.pem" .
```

**Important**: Never commit your private key to version control!

## Setting Up Ethereal Email

1. Go to [Ethereal Email](https://ethereal.email/)
2. Click "Create Ethereal Account"
3. Copy the generated credentials to your `config.json`
4. View sent emails at [https://ethereal.email/messages](https://ethereal.email/messages)

## Usage

### Run the application

```bash
python epic_fhir_client.py
```

The application will:
1. Run immediately on startup
2. Schedule subsequent runs every 24 hours
3. Keep running until manually stopped

### Run once (for testing)

If you want to run once without scheduling, modify the `main()` function or use this quick test:

```python
# test_run.py
from epic_fhir_client import EpicFHIRClient, EmailSender, LabReportService, load_config

config = load_config()
fhir_client = EpicFHIRClient(config["epic"])
email_sender = EmailSender(config["email"])
service = LabReportService(fhir_client, email_sender)
service.process_and_send_reports()
```

## Epic FHIR Authentication Flow

This application uses the **Backend App** authentication flow:

1. **Create JWT**: Generate a signed JWT with:
   - `iss` & `sub`: Your client ID
   - `aud`: Epic's token endpoint
   - `jti`: Unique identifier
   - `exp`, `nbf`, `iat`: Time claims

2. **Request Token**: POST to Epic's token endpoint with:
   - `grant_type`: client_credentials
   - `client_assertion_type`: urn:ietf:params:oauth:client-assertion-type:jwt-bearer
   - `client_assertion`: The signed JWT

3. **Use Access Token**: Include in Authorization header for FHIR API calls

## FHIR Resources Used

- **Observation**: Laboratory and vital signs data
  - Category: `laboratory` for lab results
  - Category: `vital-signs` for vitals

## Test Patients (Epic Sandbox)

| Patient ID | Name |
|------------|------|
| erXuFYUfucBZaryVksYEcMg3 | Camila Lopez |
| eq081-VQEgP8drUUqCWzHfw3 | Derrick Lin |
| egqBHVfQlt4Bw3XGXoxVxHg3 | Hyun Soo Kim |

## Interpreting Lab Results

The application classifies results based on FHIR interpretation codes:

| Code | Meaning |
|------|---------|
| N | Normal |
| H | High |
| L | Low |
| HH | Critically High |
| LL | Critically Low |
| A | Abnormal |

## Troubleshooting

### Authentication Errors

- Verify your client ID matches Epic's registration
- Ensure the private key matches the public key in your JWKS
- Check that the JWT expiration is in the future
- Verify the token URL is correct

### No Lab Results

- Epic Sandbox may have limited data for some patients
- Try the `vital-signs` category if `laboratory` returns empty
- Check that patient IDs are valid for the sandbox

### Email Not Sending

- Verify SMTP credentials are correct
- Check that port 587 is not blocked by firewall
- For Ethereal, ensure you created a valid account

## Logging

Logs are written to both console and `epic_lab_reports.log`:

```bash
# View logs
tail -f epic_lab_reports.log
```

## Running as a Service (Production)

For production deployment, consider:

1. **systemd** (Linux):
```ini
[Unit]
Description=Epic Lab Report Service
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/epic_lab_reports
ExecStart=/path/to/venv/bin/python epic_fhir_client.py
Restart=always

[Install]
WantedBy=multi-user.target
```

2. **Windows Task Scheduler**:
   - Create a basic task
   - Set trigger for every 24 hours
   - Action: Start program `python.exe` with argument `epic_fhir_client.py`

3. **Docker** (see Dockerfile if provided)

## Security Notes

1. **Never commit** `config.json` or `privatekey.pem`
2. Add to `.gitignore`:
   ```
   config.json
   *.pem
   *.key
   epic_lab_reports.log
   ```
3. In production, use environment variables or a secrets manager

## License

This project is for educational purposes as part of the Epic FHIR Bootcamp assignment.
