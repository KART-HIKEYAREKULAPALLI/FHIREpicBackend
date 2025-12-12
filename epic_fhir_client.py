"""
Epic FHIR Backend Application
Retrieves lab reports from Epic Sandbox and sends them via email.
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


class EpicFHIRClient:
    """Client for interacting with Epic FHIR API using Backend App authentication and Bulk Data."""
    
   
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Epic FHIR Client.
        
        Args:
            config: Configuration dictionary containing:
                - client_id: The Epic app client ID
                - private_key_path: Path to the private key file
                - token_url: Epic OAuth2 token endpoint
                - fhir_base_url: Epic FHIR API base URL
                - key_id: The key identifier (kid) that matches your JWKS
        """
        self.client_id = config['client_id']
        self.private_key_path = config['private_key_path']
        self.token_url = config['token_url']
        self.fhir_base_url = config['fhir_base_url']
        self.key_id = config.get('key_id', 'myapp')
        self.access_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        
        # Load private key
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
        Create a JWT client assertion for Epic authentication.
        
        Returns:
            Signed JWT string
        """
        now = int(time.time())
        
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self.token_url,
            "jti": str(uuid.uuid4()),
            "exp": now + 300
        }
        
        headers = {
            "alg": "RS384",
            "typ": "JWT",
            "kid": self.key_id
        }
        print(claims)
        print(headers)
        token = jwt.encode(
            payload=claims,
            key=self.private_key,
            algorithm="RS384",
            headers=headers
        )
        
        logger.debug(f"Client assertion JWT created with kid={self.key_id}")

        print(token)
        return token
    
    def authenticate(self) -> bool:
        """
        Authenticate with Epic OAuth2 server using client credentials flow.
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            client_assertion = self._create_client_assertion()


            
            data = {
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "scope": "system/Patient.read system/Observation.read",
                "client_assertion": client_assertion
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            print(data)
            print(headers)
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
                raise Exception("Failed to authenticate with Epic")

    def _make_bulk_request(self, method: str, url: str, headers: Optional[Dict] = None) -> requests.Response:
        """Helper for making authenticated requests to bulk data endpoints."""
        self._ensure_authenticated()
        
        default_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        if headers:
            default_headers.update(headers)
        
        try:
            response = requests.request(method, url, headers=default_headers)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except requests.exceptions.HTTPError as e:
            logger.error(f"Bulk request failed: {e.response.status_code} - {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Bulk request error: {str(e)}")
            raise

    def start_bulk_export(self, group_id: str, hours_back: int = 24) -> Optional[str]:
        """
        Initiate a Bulk Data Export job for a group.

        Args:
            group_id: The FHIR Group ID.
            hours_back: Number of hours to look back for Observations.

        Returns:
            The URL for monitoring the job status (Content-Location header) or None on failure.
        """
        self._ensure_authenticated()
        
        # Calculate date range for observations
        now = datetime.now()
        start_date = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        # Resources to export (Patient and Observation)
        resources = "Patient,Observation"
        
        # Construct the bulk export URL: [base]/Group/[id]/$export
        export_url = f"{self.fhir_base_url}/Group/{group_id}/$export"
        
        # Bulk Data Export parameters
        params = {
            "_outputFormat": "application/fhir+ndjson",
            "_type": resources,
            "patient.Observation.date": f"ge{start_date}", # Filter observations by date
            "patient.Observation.category": "laboratory" # Filter observations by category
        }
        
        headers = {
            "Accept": "application/fhir+json",
            "Prefer": "respond-async" # REQUIRED for asynchronous export
        }
        
        try:
            logger.info(f"Starting bulk export for Group {group_id}...")
            response = requests.get(export_url, headers=self._build_auth_headers(headers), params=params)
            
            if response.status_code == 202:
                # Job accepted, monitoring URL is in the Content-Location header
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
        """
        Check the status of the Bulk Data Export job.

        Args:
            status_url: The URL to monitor the job.

        Returns:
            The response JSON (completion manifest) if the job is complete (status 200),
            None if still processing (status 202).
        """
        try:
            response = self._make_bulk_request("GET", status_url)
            
            if response.status_code == 202:
                # Job still running
                logger.info("Bulk export job status: In progress (202 Accepted)")
                retry_after = response.headers.get("Retry-After", "30")
                logger.info(f"  Waiting {retry_after} seconds before next check.")
                return None
            elif response.status_code == 200:
                # Job complete
                logger.info("Bulk export job status: Complete (200 OK)")
                return response.json()
            else:
                logger.error(f"Unexpected status response: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.HTTPError as e:
            # Check for error status (4xx or 5xx)
            if e.response.status_code in [404, 500]:
                 logger.error(f"Bulk export status check failed: {e.response.status_code} - {e.response.text}")
                 return {"error": e.response.text} # Return error dict to signal failure
            raise # Re-raise other errors

    def download_and_process_ndjson(self, manifest: Dict) -> Tuple[Dict[str, Dict], Dict[str, List]]:
        """
        Download and process the NDJSON files from the completion manifest.

        Args:
            manifest: The JSON response from the completed export job.

        Returns:
            A tuple: (patients_map, observations_map)
                patients_map: {patient_id: patient_resource}
                observations_map: {patient_id: [observation_resource, ...]}
        """
        patients_map = {}
        observations_map = {}
        
        output_files = manifest.get("output", [])
        
        for file_entry in output_files:
            file_type = file_entry.get("type")
            file_url = file_entry.get("url")
            
            if not file_url:
                continue
            
            try:
                logger.info(f"Downloading {file_type} file from {file_url}...")
                response = self._make_bulk_request("GET", file_url, headers={"Accept": "application/fhir+ndjson"})
                
                # The content is a stream of JSON objects separated by newlines
                content = response.text
                
                # Use io.StringIO to treat the content as a file for reading lines
                for line in io.StringIO(content):
                    line = line.strip()
                    if not line:
                        continue
                        
                    resource = json.loads(line)
                    resource_type = resource.get("resourceType")
                    
                    if resource_type == "Patient":
                        patient_id = resource["id"]
                        patients_map[patient_id] = resource
                        
                    elif resource_type == "Observation":
                        # Extract patient ID from the subject reference
                        subject_ref = resource.get("subject", {}).get("reference", "")
                        if subject_ref.startswith("Patient/"):
                            patient_id = subject_ref.replace("Patient/", "")
                            
                            if patient_id not in observations_map:
                                observations_map[patient_id] = []
                            observations_map[patient_id].append(resource)
                            
                logger.info(f"Successfully processed {len(patients_map)} patients and {sum(len(v) for v in observations_map.values())} observations from {file_type}.")

            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to download or parse NDJSON file ({file_type}): {str(e)}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON line in NDJSON file ({file_type}): {str(e)}")


        return patients_map, observations_map

    def _build_auth_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Helper to combine authorization and other headers."""
        self._ensure_authenticated()
        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }
        if custom_headers:
            headers.update(custom_headers)
        return headers

    # The original get_patients and observation methods are no longer needed for the bulk process, 
    # but I'll keep a simple version of get_patient_details as a utility.
    def get_patient_details(self, patient_id: str) -> Optional[Dict]:
        """
        Get patient details by ID (using direct search as a utility).
        
        Args:
            patient_id: The patient's FHIR ID
            
        Returns:
            Patient resource or None
        """
        # This is for utility/fallback, the main flow uses bulk export now.
        url = f"{self.fhir_base_url}/Patient/{patient_id}"
        headers = self._build_auth_headers({"Accept": "application/json"})
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()

            # Extract patient name
            names = result.get("name", [])
            full_name = "Unknown"
            if names:
                name_parts = names[0]
                given = " ".join(name_parts.get("given", []))
                family = name_parts.get("family", "")
                full_name = f"{given} {family}".strip()
            
            return {
                "id": patient_id,
                "name": full_name,
                "resource": result
            }
        except Exception as e:
            logger.warning(f"Failed to fetch Patient/{patient_id} directly: {e}")
            return None

    # The following methods are now obsolete or replaced by the bulk workflow:
    # get_patients
    # get_group
    # get_patients_from_group
    # get_lab_observations (replaced by bulk data workflow in LabReportService)
    # get_all_observations (replaced by bulk data workflow in LabReportService)


class LabReportFormatter:
    # ... (No changes needed to LabReportFormatter, as it works with raw FHIR Observation dicts) ...
    """Formats lab reports for email presentation."""
    
    @staticmethod
    def format_observation(obs: Dict) -> Dict[str, Any]:
        """
        Extract and format relevant information from a FHIR Observation.
        
        Args:
            obs: FHIR Observation resource
            
        Returns:
            Formatted observation dictionary
        """
        # Get test name from code
        code_info = obs.get("code", {})
        test_name = "Unknown Test"
        if "text" in code_info:
            test_name = code_info["text"]
        elif "coding" in code_info and code_info["coding"]:
            test_name = code_info["coding"][0].get("display", "Unknown Test")
        
        # Get value
        value = "N/A"
        unit = ""
        if "valueQuantity" in obs:
            value = obs["valueQuantity"].get("value", "N/A")
            unit = obs["valueQuantity"].get("unit", "")
        elif "valueString" in obs:
            value = obs["valueString"]
        elif "valueCodeableConcept" in obs:
            value = obs["valueCodeableConcept"].get("text", "N/A")
        
        # Get reference range
        reference_range = "N/A"
        if "referenceRange" in obs and obs["referenceRange"]:
            range_info = obs["referenceRange"][0]
            low = range_info.get("low", {}).get("value", "")
            high = range_info.get("high", {}).get("value", "")
            if low and high:
                reference_range = f"{low} - {high}"
            elif "text" in range_info:
                reference_range = range_info["text"]
        
        # Determine if abnormal
        interpretation = "Normal"
        is_abnormal = False
        if "interpretation" in obs and obs["interpretation"]:
            interp_code = obs["interpretation"][0].get("coding", [{}])[0]
            interpretation = interp_code.get("display", interp_code.get("code", "Normal"))
            abnormal_codes = ["H", "L", "HH", "LL", "A", "AA", "HU", "LU"]
            is_abnormal = interp_code.get("code", "") in abnormal_codes
        
        # Get date
        effective_date = obs.get("effectiveDateTime", obs.get("issued", "Unknown"))
        
        # Get status
        status = obs.get("status", "unknown")
        
        return {
            "test_name": test_name,
            "value": f"{value} {unit}".strip(),
            "reference_range": reference_range,
            "interpretation": interpretation,
            "is_abnormal": is_abnormal,
            "date": effective_date,
            "status": status,
            # Note: Category here will always be 'laboratory' due to the bulk filter.
            "category": obs.get("category", [{}])[0].get("coding", [{}])[0].get("code", "unknown") 
        }
    
    @staticmethod
    def format_report_html(patient_name: str, observations: List[Dict]) -> str:
        """
        Format observations as HTML for email.
        
        Args:
            patient_name: Name of the patient
            observations: List of formatted observations
            
        Returns:
            HTML string
        """
        abnormal = [o for o in observations if o["is_abnormal"]]
        normal = [o for o in observations if not o["is_abnormal"]]
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #555; margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .abnormal {{ background-color: #ffcccc !important; }}
                .normal {{ background-color: #ccffcc !important; }}
                .summary {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .timestamp {{ color: #888; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <h1>Lab Report for {patient_name}</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="summary">
                <strong>Summary:</strong><br>
                Total Results: {len(observations)}<br>
                Normal Results: {len(normal)}<br>
                Abnormal Results: {len(abnormal)}
            </div>
        """
        
        if abnormal:
            html += """
            <h2 style="color: #cc0000;">⚠️ Abnormal Results</h2>
            <table>
                <tr>
                    <th>Test</th>
                    <th>Value</th>
                    <th>Reference Range</th>
                    <th>Interpretation</th>
                    <th>Date</th>
                </tr>
            """
            for obs in abnormal:
                html += f"""
                <tr class="abnormal">
                    <td>{obs['test_name']}</td>
                    <td><strong>{obs['value']}</strong></td>
                    <td>{obs['reference_range']}</td>
                    <td>{obs['interpretation']}</td>
                    <td>{obs['date']}</td>
                </tr>
                """
            html += "</table>"
        
        if normal:
            html += """
            <h2 style="color: #009900;">✓ Normal Results</h2>
            <table>
                <tr>
                    <th>Test</th>
                    <th>Value</th>
                    <th>Reference Range</th>
                    <th>Interpretation</th>
                    <th>Date</th>
                </tr>
            """
            for obs in normal:
                html += f"""
                <tr class="normal">
                    <td>{obs['test_name']}</td>
                    <td>{obs['value']}</td>
                    <td>{obs['reference_range']}</td>
                    <td>{obs['interpretation']}</td>
                    <td>{obs['date']}</td>
                </tr>
                """
            html += "</table>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def format_report_text(patient_name: str, observations: List[Dict]) -> str:
        """
        Format observations as plain text for email.
        
        Args:
            patient_name: Name of the patient
            observations: List of formatted observations
            
        Returns:
            Plain text string
        """
        abnormal = [o for o in observations if o["is_abnormal"]]
        normal = [o for o in observations if not o["is_abnormal"]]
        
        text = f"""
LAB REPORT FOR {patient_name.upper()}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*60}
SUMMARY
{'='*60}
Total Results: {len(observations)}
Normal Results: {len(normal)}
Abnormal Results: {len(abnormal)}

"""
        
        if abnormal:
            text += f"""
{'='*60}
⚠️  ABNORMAL RESULTS
{'='*60}
"""
            for obs in abnormal:
                text += f"""
Test: {obs['test_name']}
Value: {obs['value']}
Reference Range: {obs['reference_range']}
Interpretation: {obs['interpretation']}
Date: {obs['date']}
{'-'*40}
"""
        
        if normal:
            text += f"""
{'='*60}
✓ NORMAL RESULTS
{'='*60}
"""
            for obs in normal:
                text += f"""
Test: {obs['test_name']}
Value: {obs['value']}
Reference Range: {obs['reference_range']}
Date: {obs['date']}
{'-'*40}
"""
        
        return text


class EmailSender:
    # ... (No changes needed to EmailSender) ...
    """Handles sending emails via SMTP."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize EmailSender with SMTP configuration.
        
        Args:
            config: Dictionary containing:
                - smtp_host: SMTP server hostname
                - smtp_port: SMTP server port
                - smtp_user: SMTP username
                - smtp_password: SMTP password
                - from_email: Sender email address
                - to_email: Recipient email address
        """
        self.smtp_host = config['smtp_host']
        self.smtp_port = config['smtp_port']
        self.smtp_user = config['smtp_user']
        self.smtp_password = config['smtp_password']
        self.from_email = config['from_email']
        self.to_email = config['to_email']
    
    def send_email(self, subject: str, text_content: str, html_content: str) -> bool:
        """
        Send an email with both text and HTML content.
        
        Args:
            subject: Email subject
            text_content: Plain text content
            html_content: HTML content
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            
            # Attach both text and HTML versions
            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Connect to SMTP server and send
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, self.to_email, msg.as_string())
            
            logger.info(f"Email sent successfully to {self.to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False


class LabReportService:
    """Main service that orchestrates lab report retrieval and notification using Bulk Data."""
    
    def __init__(self, fhir_client: EpicFHIRClient, email_sender: EmailSender, group_id: str = None):
        """
        Initialize the Lab Report Service.
        
        Args:
            fhir_client: Configured Epic FHIR client
            email_sender: Configured email sender
            group_id: FHIR Group ID to fetch patients from (REQUIRED for Bulk Export)
        """
        self.fhir_client = fhir_client
        self.email_sender = email_sender
        self.formatter = LabReportFormatter()
        self.group_id = group_id
        self.hours_back = 24 # Look back 24 hours for lab results
    
    def process_and_send_reports(self):
        """Process lab reports for all patients in the group and send email notifications."""
        logger.info("Starting lab report processing using Bulk Data Access...")
        
        if not self.group_id:
            logger.error("Group ID is required for FHIR Bulk Export. Aborting.")
            return

        try:
            # 1. Authenticate first
            if not self.fhir_client.authenticate():
                logger.error("Failed to authenticate with Epic. Aborting.")
                return

            # 2. Start Bulk Export job
            status_url = self.fhir_client.start_bulk_export(self.group_id, self.hours_back)
            if not status_url:
                logger.error("Failed to start bulk export job. Aborting.")
                return

            # 3. Poll for status (Monitor continuously)
            manifest = None
            start_time = time.time()
            timeout_minutes = 5 # Set a timeout for the job

            while time.time() - start_time < (timeout_minutes * 60):
                time.sleep(10) # Wait 10 seconds between checks
                manifest = self.fhir_client.check_export_status(status_url)
                
                if manifest:
                    if "error" in manifest:
                        logger.error(f"Bulk export failed during status check: {manifest['error']}")
                        return
                    # Job completed successfully
                    break
            
            if not manifest:
                logger.error(f"Bulk export job timed out after {timeout_minutes} minutes. Aborting.")
                return
            
            # 4. Download and process NDJSON files
            logger.info("Downloading and processing NDJSON files...")
            patients_map, observations_map = self.fhir_client.download_and_process_ndjson(manifest)
            
            if not patients_map:
                logger.info("No patients found in the bulk export. Aborting.")
                return

            # 5. Format and prepare reports
            all_reports = []
            
            for patient_id, patient_resource in patients_map.items():
                patient_name = patient_resource.get("name", [{}])[0].get("text", "Unknown Patient")
                
                observations = observations_map.get(patient_id, [])
                
                # We only process if there are observations (lab reports) for this patient
                if observations:
                    logger.info(f"Formatting {len(observations)} lab observations for {patient_name} ({patient_id})")
                    
                    # Format observations
                    formatted_obs = [
                        self.formatter.format_observation(obs) 
                        for obs in observations
                    ]
                    
                    # Filter for only laboratory results (redundant due to bulk filter, but good for safety)
                    lab_obs = [o for o in formatted_obs if o.get("category") == "laboratory"]
                    
                    if lab_obs:
                        all_reports.append({
                            "patient_name": patient_name,
                            "patient_id": patient_id,
                            "observations": lab_obs # Should only contain laboratory results
                        })
                    else:
                        logger.warning(f"No laboratory observations found after formatting for patient {patient_name}")
                else:
                    logger.info(f"No lab observations found in NDJSON for patient {patient_name}")

            # 6. Send Email
            if all_reports:
                # Create combined email content
                group_info = f" (Group: {self.group_id})"
                subject = f"Lab Reports{group_info} - {datetime.now().strftime('%Y-%m-%d')}"
                
                # Build combined HTML
                combined_html = """
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        .patient-section {{ margin-bottom: 40px; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                        .group-info {{ background-color: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
                    </style>
                </head>
                <body>
                    <h1>Daily Lab Reports Summary</h1>
                    <div class="group-info">
                        <strong>Report Date:</strong> {report_date}<br>
                        <strong>Group ID:</strong> {group_id}<br>
                        <strong>Total Patients with Reports:</strong> {patient_count}
                    </div>
                """.format(
                    report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    group_id=self.group_id,
                    patient_count=len(all_reports)
                )
                
                combined_text = f"""
DAILY LAB REPORTS SUMMARY
Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Group ID: {self.group_id}
Total Patients with Reports: {len(all_reports)}
{'='*60}

"""
                
                for report in all_reports:
                    combined_html += '<div class="patient-section">'
                    combined_html += self.formatter.format_report_html(
                        report["patient_name"],
                        report["observations"]
                    )
                    combined_html += '</div>'
                    
                    combined_text += self.formatter.format_report_text(
                        report["patient_name"],
                        report["observations"]
                    )
                    combined_text += "\n\n"
                
                combined_html += "</body></html>"
                
                # Send the email
                success = self.email_sender.send_email(
                    subject,
                    combined_text,
                    combined_html
                )
                
                if success:
                    logger.info("Lab reports email sent successfully!")
                else:
                    logger.error("Failed to send lab reports email")
            else:
                logger.info("No lab reports found for any patients in the bulk export.")
                
        except Exception as e:
            logger.error(f"Fatal error processing lab reports: {str(e)}")
            # Log full traceback for better debugging
            import traceback
            logger.error(traceback.format_exc())
            # Don't re-raise as it's the main scheduled job

def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Load configuration from JSON file."""
    with open(config_path, 'r') as f:
        return json.load(f)


def run_scheduled_job(service: LabReportService):
    """Run the scheduled job."""
    logger.info("Running scheduled lab report job...")
    service.process_and_send_reports()
    logger.info("Scheduled job completed")


def main():
    """Main entry point for the application."""
    logger.info("Epic FHIR Lab Report Service Starting...")
    
    # Load configuration
    try:
        config = load_config()
    except FileNotFoundError:
        logger.error("config.json not found. Please create it from config.example.json")
        return
    
    # Initialize clients
    fhir_client = EpicFHIRClient(config["epic"])
    email_sender = EmailSender(config["email"])
    
    # Get group_id from config (REQUIRED for Bulk Export)
    group_id = config.get("group_id")
    if group_id:
        logger.info(f"Using Group ID for Bulk Export: {group_id}")
    else:
        logger.error("Group ID is missing in config.json. Required for Bulk Export.")
        return # Cannot proceed without a Group ID for Bulk Export
    
    # Initialize service with group_id
    service = LabReportService(fhir_client, email_sender, group_id=group_id)
    
    # Run immediately on startup
    logger.info("Running initial report...")
    service.process_and_send_reports()
    
    # Schedule to run every 24 hours
    schedule.every(24).hours.do(run_scheduled_job, service=service)
    
    logger.info("Scheduler started. Running every 24 hours...")
    
    # Keep the scheduler running
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute


if __name__ == "__main__":
    main()