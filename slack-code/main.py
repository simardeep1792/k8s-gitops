import base64
import json
import os
import requests
import functions_framework
from datetime import datetime
from google.cloud import secretmanager

client = secretmanager.SecretManagerServiceClient()

def access_secret_version(secret_id, project_id):
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    payload = response.payload.data.decode("UTF-8")
    return payload

@functions_framework.cloud_event
def send_error_logs_to_slack(event):
    project_id = os.getenv("GCP_PROJECT")
    slack_webhook_url = access_secret_version(secret_id="hopic-slack-url", project_id=project_id)
    message_data = base64.b64decode(event.data['message']['data']).decode('utf-8')
    log_entry = json.loads(message_data)
    slack_message = format_slack_message(log_entry)
    response = requests.post(slack_webhook_url, headers={'Content-Type': 'application/json'}, data=slack_message)
    if response.status_code != 200:
        raise ValueError(f"Request to Slack returned an error {response.status_code}, the response is:\n{response.text}")

def format_slack_message(log_entry):
    insert_id = log_entry.get('insertId')
    severity = log_entry.get('severity', 'INFO')
    timestamp = log_entry.get('timestamp', 'No timestamp provided')

    if 'jsonPayload' in log_entry:
        payload = log_entry['jsonPayload']
        exception_details = payload.get('exception', 'No exception details provided').replace('```', '\\`\\`\\`')
        event_message = payload.get('event', 'No specific event message provided')
        func_name = payload.get('func_name', 'N/A')
        lineno = str(payload.get('lineno', 'N/A'))
        logger = payload.get('logger', 'N/A')
    elif 'textPayload' in log_entry:
        exception_details = log_entry.get('textPayload', 'No text payload provided')
        event_message = 'N/A' 
        func_name, lineno, logger = 'N/A', 'N/A', 'N/A'

    container_name = log_entry.get('resource', {}).get('labels', {}).get('container_name', 'Unknown')
    pod_name = log_entry.get('resource', {}).get('labels', {}).get('pod_name', 'Unknown')
    cluster_name = log_entry.get('resource', {}).get('labels', {}).get('cluster_name', 'Unknown')
    namespace_name = log_entry.get('resource', {}).get('labels', {}).get('namespace_name', 'Unknown')

    try:
        slack_timestamp = int(datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp())
    except ValueError:
        slack_timestamp = None

    slack_message = {
        "attachments": [
            {
                "color": "#ff0000" if severity.upper() == "ERROR" else "#36a64f",
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True},
                    {"title": "Log Entry ID", "value": insert_id, "short": False},
                    {"title": "Container", "value": container_name, "short": True},
                    {"title": "Pod", "value": pod_name, "short": True},
                    {"title": "Cluster", "value": cluster_name, "short": True},
                    {"title": "Namespace", "value": namespace_name, "short": True},
                    {"title": "Event", "value": event_message, "short": False},
                    {"title": "Function Name", "value": func_name, "short": True},
                    {"title": "Line Number", "value": lineno, "short": True},
                    {"title": "Logger", "value": logger, "short": True},
                    {"title": "Details", "value": f"```{exception_details}```", "short": False}
                ],
                "footer": "Google Cloud Function",
                "ts": slack_timestamp
            }
        ]
    }

    return json.dumps(slack_message)