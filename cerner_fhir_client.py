"""
Oracle Health (Cerner) FHIR Backend Application
Retrieves lab reports from Cerner Sandbox and sends them via email.
Runs every 24 hours as specified in the assignment.
"""

import jwt
import time
import uuid
import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
import logging
import schedule
from pathlib import Path
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cerner_lab_reports.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CernerFHIRClient:
    """Client for interacting with Cerner FHIR API using Backend App authentication and Bulk Data."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Cerner FHIR Client.
        
        Args:
            config: Configuration dictionary containing:
                - client_id: The Cerner app client ID
                - private_key_path: Path to the private key file
                - token_url: Cerner OAuth2 token endpoint
                - fhir_base_url: Cerner FHIR API base URL
                - key_id: The key identifier (kid) that matches your JWKS in Cerner Console
        """
        self.client_id = config['client_id']
        self.private_key_path = config['private_key_path']
        self.token_url = config['token_url']
        self.fhir_base_url = config['fhir_base_url']
        self.key_id = config.get('key_id')  # Cerner REQUIRES this to match your JWKS kid
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        
        # Scopes for Cerner Bulk Data (System level)
        # Cerner typically requires specific system scopes
        self.scopes = config.get("scopes", "system/Patient.read system/Observation.read")
        
        self._load_private_key()
    
    def _load_private_key(self):
        """Load the private key from file."""
        try:
            with open(self.private_key_path, 'r') as f:
                self.private_key = f.read()
            logger.info("Private key loaded successfully")
        except FileNotFoundError:
            logger.error(f"Private key not found at {self.private_key_path}")
            raise
    
    def _create_client_assertion(self) -> str:
        """
        Create a JWT client assertion for Cerner authentication.
        """
        now = int(time.time())
        
        # Cerner Specific: 'aud' must strictly match the Token URL
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.token_url, 
            "jti": str(uuid.uuid4()),
            "exp": now + 280
        }
        
        # Cerner Specific: 'kid' in header is MANDATORY and must match JWKS
        headers = {
            "alg": "RS384",
            "typ": "JWT",
            "kid": self.key_id 
        }
        
        token = jwt.encode(
            payload=claims,
            key=self.private_key,
            algorithm="RS384",
            headers=headers
        )
        
        logger.debug(f"Client assertion JWT created with kid={self.key_id}")
        return token
    
    def authenticate(self) -> bool:
        """
        Authenticate with Cerner OAuth2 server using SMART Backend Services flow.
        """
        try:
            client_assertion = self._create_client_assertion()
            
            data = {
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "scope": self.scopes
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            
            response = requests.post(
                self.token_url,
                data=data,
                headers=headers
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data.get("access_token")
                expires_in = token_data.get("expires_in", 3600)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                logger.info("Authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    def _ensure_authenticated(self):
        """Ensure we have a valid access token."""
        if not self.access_token or (self.token_expiry and datetime.now() >= self.token_expiry):
            if not self.authenticate():
                raise Exception("Failed to authenticate with Cerner")

    def _make_bulk_request(self, method: str, url: str, headers: Optional[Dict] = None) -> requests.Response:
        """Helper for making authenticated requests."""
        self._ensure_authenticated()
        
        default_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        if headers:
            default_headers.update(headers)
        
        try:
            response = requests.request(method, url, headers=default_headers)
            response.raise_for_status() 
            return response
        except requests.exceptions.HTTPError as e:
            logger.error(f"Bulk request failed: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Bulk request error: {str(e)}")
            raise

    def start_bulk_export(self, group_id: str, hours_back: int = 24) -> Optional[str]:
        """
        Initiate a Bulk Data Export job (Group level).
        """
        self._ensure_authenticated()
        
        now = datetime.now()
        start_date = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Cerner often requires 'system' export or specific group export
        export_url = f"{self.fhir_base_url}/Group/{group_id}/$export"
        
        params = {
            "_outputFormat": "application/fhir+ndjson",
            "_type": "Patient,Observation",
            "_since": start_date  # Cerner uses _since for time filtering
        }
        
        # Cerner strictly requires application/fhir+json for the kickoff Accept header
        headers = {
            "Accept": "application/fhir+json",
            "Prefer": "respond-async"
        }
        
        try:
            logger.info(f"Starting Cerner bulk export for Group {group_id}...")
            response = requests.get(export_url, headers=self._build_auth_headers(headers), params=params)
            
            if response.status_code > 200 and response.status_code < 300:
                status_url = response.headers.get("Content-Location")
                if status_url:
                    logger.info(f"Bulk export job started. Status URL: {status_url}")
                    return status_url
                else:
                    logger.error("Bulk export started, but missing Content-Location header.")
                    return None
            else:
                logger.error(f"Failed to start bulk export: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error starting bulk export: {str(e)}")
            return None

    def check_export_status(self, status_url: str) -> Optional[Dict]:
        """Check status of the export job."""
        try:
            response = self._make_bulk_request("GET", status_url)
            
            if response.status_code == 202:
                # Job is still running
                retry_after = response.headers.get("Retry-After", "60")
                logger.info(f"Bulk export job still running (202). Cerner suggests waiting {retry_after}s.")
                return None
            
            elif response.status_code == 200:
                # Job is complete!
                logger.info("Bulk export job status: Complete (200 OK)")
                return response.json()
            
            else:
                logger.error(f"Unexpected status response: {response.status_code} - {response.text}")
                return {"job_error": f"Unexpected status: {response.status_code}"}
                
        except requests.exceptions.HTTPError as e:
            # Real failures (4xx, 5xx)
            logger.error(f"Bulk export status check failed: {e.response.status_code} - {e.response.text}")
            return {"job_error": e.response.text}
        

    def download_and_process_ndjson(self, manifest: Dict) -> Tuple[Dict[str, Dict], Dict[str, List]]:
        """Download and process NDJSON files."""
        patients_map = {}
        observations_map = {}
        
        output_files = manifest.get("output", [])
        
        for file_entry in output_files:
            file_type = file_entry.get("type")
            file_url = file_entry.get("url")
            
            if not file_url:
                continue
            
            try:
                logger.info(f"Downloading {file_type} file...")
                # Cerner usually requires the SAME access token for downloading files
                response = self._make_bulk_request("GET", file_url, headers={"Accept": "application/fhir+ndjson"})
                
                content = response.text
                for line in io.StringIO(content):
                    line = line.strip()
                    if not line: continue
                        
                    resource = json.loads(line)
                    resource_type = resource.get("resourceType")
                    
                    if resource_type == "Patient":
                        patients_map[resource["id"]] = resource
                    elif resource_type == "Observation":
                        subject_ref = resource.get("subject", {}).get("reference", "")
                        if subject_ref.startswith("Patient/"):
                            pat_id = subject_ref.split("/")[-1]
                            if pat_id not in observations_map:
                                observations_map[pat_id] = []
                            observations_map[pat_id].append(resource)
                            
                logger.info(f"Processed {file_type} file.")

            except Exception as e:
                logger.error(f"Failed to process file ({file_type}): {str(e)}")

        return patients_map, observations_map

    def _build_auth_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        self._ensure_authenticated()
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if custom_headers: headers.update(custom_headers)
        return headers


# --- Service and Formatters (Identical to previous logic, kept for completeness) ---

class LabReportFormatter:
    @staticmethod
    def format_observation(obs: Dict) -> Dict[str, Any]:
        code_info = obs.get("code", {})
        test_name = code_info.get("text") or (code_info.get("coding", [{}])[0].get("display")) or "Unknown Test"
        
        value = "N/A"
        unit = ""
        if "valueQuantity" in obs:
            value = obs["valueQuantity"].get("value", "N/A")
            unit = obs["valueQuantity"].get("unit", "")
        elif "valueString" in obs:
            value = obs["valueString"]
        elif "valueCodeableConcept" in obs:
            value = obs["valueCodeableConcept"].get("text", "N/A")
            
        return {
            "test_name": test_name,
            "value": f"{value} {unit}".strip(),
            "date": obs.get("effectiveDateTime", obs.get("issued", "Unknown")),
            "status": obs.get("status", "unknown"),
            "category": "laboratory" 
        }

    @staticmethod
    def format_report_html(patient_name: str, observations: List[Dict]) -> str:
        html = f"<h2>Lab Report for {patient_name}</h2><table border='1'><tr><th>Test</th><th>Value</th><th>Date</th></tr>"
        for obs in observations:
            html += f"<tr><td>{obs['test_name']}</td><td>{obs['value']}</td><td>{obs['date']}</td></tr>"
        html += "</table>"
        return html
    
    @staticmethod
    def format_report_text(patient_name: str, observations: List[Dict]) -> str:
        text = f"LAB REPORT FOR {patient_name}\n" + "="*30 + "\n"
        for obs in observations:
            text += f"Test: {obs['test_name']} | Value: {obs['value']} | Date: {obs['date']}\n"
        return text


class EmailSender:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def send_email(self, subject: str, text: str, html: str) -> bool:
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config['from_email']
            msg['To'] = self.config['to_email']
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            with smtplib.SMTP(self.config['smtp_host'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['smtp_user'], self.config['smtp_password'])
                server.sendmail(self.config['from_email'], self.config['to_email'], msg.as_string())
            logger.info("Email sent.")
            return True
        except Exception as e:
            logger.error(f"Email failed: {e}")
            return False


class LabReportService:
    def __init__(self, fhir_client: CernerFHIRClient, email_sender: EmailSender, group_id: str):
        self.client = fhir_client
        self.email = email_sender
        self.group_id = group_id
        self.formatter = LabReportFormatter()

    def process_and_send_reports(self):
        logger.info("Starting Lab Report Service...")
        
        # 1. Start Bulk Export
        status_url = self.client.start_bulk_export(self.group_id)
        if not status_url:
            logger.error("Could not start export job. Aborting.")
            return

        # 2. Monitor Status (Updated for 20 mins timeout, 1 min interval)
        manifest = None
        start_time = time.time()
        timeout_seconds = 20 * 60  # 20 Minutes
        
        logger.info("Polling for export completion (Timeout: 20 mins)...")
        
        while (time.time() - start_time) < timeout_seconds:
            manifest = self.client.check_export_status(status_url)
            
            if manifest:
                # Check if it's a real success or a failure message we constructed
                if "job_error" in manifest:
                    logger.error(f"Job failed with error: {manifest['job_error']}")
                    return
                
                # Success! Break the loop.
                logger.info("Export manifest received successfully.")
                break
            
            # If manifest is None, job is still running (202). Wait and retry.
            time.sleep(60) 
        
        # 3. Validation
        if not manifest:
            logger.error("Export timed out after 20 minutes.")
            return
            
        # CRITICAL FIX: Standard FHIR Manifests may have an empty "error": [] list. 
        # We only fail if "output" is completely missing.
        if "output" not in manifest:
            logger.error(f"Export completed but 'output' is missing in manifest: {manifest}")
            return

        # 4. Download Data
        logger.info("Downloading NDJSON files from manifest...")
        patients, observations = self.client.download_and_process_ndjson(manifest)

        # 5. Process & Email
        if not patients:
            logger.info("No patient data found in the export.")
            return

        logger.info(f"Processing reports for {len(patients)} patients...")
        all_reports_html = ""
        all_reports_text = ""
        
        count = 0
        for pid, pat in patients.items():
            obs_list = observations.get(pid, [])
            if not obs_list: continue
            
            pat_name = pat.get("name", [{}])[0].get("text", "Unknown Patient")
            fmt_obs = [self.formatter.format_observation(o) for o in obs_list]
            
            all_reports_html += self.formatter.format_report_html(pat_name, fmt_obs)
            all_reports_text += self.formatter.format_report_text(pat_name, fmt_obs) + "\n"
            count += 1

        if count > 0:
            logger.info(f"Sending email with reports for {count} patients...")
            success = self.email.send_email(
                f"Cerner Lab Reports - {datetime.now().strftime('%Y-%m-%d')}",
                all_reports_text,
                "<html><body>" + all_reports_html + "</body></html>"
            )
            if success:
                logger.info(" Workflow completed successfully.")
        else:
            logger.info("No observations found for the patients.")


def main():
    try:
        with open('config.json', 'r') as f: config = json.load(f)
    except Exception:
        logger.error("config.json missing.")
        return

    # Initialize Cerner Client
    client = CernerFHIRClient(config["cerner"]) # Expecting "cerner" block in config
    email = EmailSender(config["email"])
    
    service = LabReportService(client, email, config.get("group_id"))
    
    # Run once immediately
    service.process_and_send_reports()
    
    # Schedule
    schedule.every(24).hours.do(service.process_and_send_reports)
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()