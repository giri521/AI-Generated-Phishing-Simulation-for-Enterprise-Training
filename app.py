import os
import requests
import json
import smtplib
import ssl
import time
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, make_response
import pandas as pd
from io import StringIO, BytesIO
# qrcode removed as per user request, client-side QR used
# import qrcode 

# --- Configuration and Security Warning ---

# ⚠️ WARNING: DO NOT USE HARDCODED CREDENTIALS IN PRODUCTION
HARDCODED_USERNAME = "admin"
HARDCODED_PASSWORD = "password123"

# --- Backendless Configuration ---
BACKENDLESS_APP_ID = "AC2007DC-0DB9-459E-8106-C9F017F7A265"
BACKENDLESS_REST_API_KEY = "6E964334-AA21-40EC-8BF0-F67D19241C28"
BACKENDLESS_BASE_URL = f"https://api.backendless.com/{BACKENDLESS_APP_ID}/{BACKENDLESS_REST_API_KEY}/data/Campaigns"
PHISHING_ATTEMPT_TABLE_URL = f"https://api.backendless.com/{BACKENDLESS_APP_ID}/{BACKENDLESS_REST_API_KEY}/data/PhishingAttempts"
QUIZ_RESULT_TABLE_URL = f"https://api.backendless.com/{BACKENDLESS_APP_ID}/{BACKENDLESS_REST_API_KEY}/data/QuizResults" # NEW TABLE FOR QUIZ RESULTS

# --- Gemini API Configuration ---
GEMINI_API_KEY = "AIzaSyDJrsc1ItWcK0YLezFAxBQaKSyppncHTMg"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={GEMINI_API_KEY}"

# --- Gmail SMTP settings (Ensure this is correct and uses an App Password) ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
EMAIL_USER = "girivennapusa8@gmail.com"
EMAIL_PASS = "wzrn qcno juwf jgqy".replace(" ", "")

# --- PHISHING SIMULATION CONFIG ---
PHISHING_LANDING_URL = "https://ai-generated-phishing-simulation-for.onrender.com/training-trap" # Changed to redirect to training route


# Flask initialization
app = Flask(__name__)
# Generate a random secret key for session management
app.secret_key = os.urandom(24)

# --- Helper Functions ---

def check_auth():
    """Checks if the 'logged_in' flag is set in the user session."""
    return 'logged_in' in session and session['logged_in']

def generate_content_with_gemini(campaign_name, description, method, campaign_id_for_tracking="TEST"):
    """Generates safe, professional campaign content using the Gemini API."""
    
    # Use 'training-trap' route for tracking so training page is displayed after click
    tracking_url = f"https://ai-generated-phishing-simulation-for.onrender.com/training-trap?cid={campaign_id_for_tracking}"

    if method == 'email':
        system_prompt = f"You are a professional marketing copywriter. Write the shortest possible, yet compelling, email body for a product announcement or newsletter. It should be based on a single, powerful sentence (max 150 characters total). Include a clear call-to-action link, using the placeholder HTML '<a href=\"{tracking_url}\">Click Here Now</a>' at the end, followed by a professional signature."
        user_query = f"The campaign is titled '{campaign_name}'. The description is: '{description}'. Do not include a subject line in the response."
        subject = f"[Announcement] {campaign_name}: Don't Miss Out!"
    elif method == 'qr':
        # For QR, the content is just the tracking URL
        return {"subject": f"QR Code Link for: {campaign_name}", "body": tracking_url}
    else:
        return {"subject": None, "body": "Unknown campaign method."}

    payload = {
        "contents": [{ "parts": [{ "text": user_query }] }],
        "systemInstruction": { "parts": [{ "text": system_prompt }] },
    }

    try:
        # Simple retry logic
        for i in range(3):
            response = requests.post(
                GEMINI_API_URL,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=20
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Content generation failed.')
                return {"subject": subject, "body": content}
            
            if response.status_code in [429, 503]:
                time.sleep(2 ** i)
            else:
                response.raise_for_status()
                
        return {"subject": None, "body": "Error: Content generation failed after retries."}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Gemini API general request failed: {e}")
        return {"subject": None, "body": f"Error: AI content generation failed (Network/Timeout). Details: {e}"}

def send_email(recipient, subject, body):
    """Sends an email using the provided Gmail SMTP credentials."""
    msg = EmailMessage()
    msg.set_content(body, subtype='html' if '<a href' in body else 'plain')
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = recipient

    context = ssl.create_default_context()
    
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"SMTP Email sending failed to {recipient}: {e}")
        return False

def fetch_all_campaigns():
    """Fetches all campaigns from Backendless and returns them as a list."""
    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Campaign Viewer"
    }
    try:
        response = requests.get(BACKENDLESS_BASE_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            app.logger.error(f"Backendless fetch error ({response.status_code}): {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to connect to Backendless for fetching: {e}")
        return []

def fetch_all_phishing_attempts():
    """Fetches ALL phishing attempts from Backendless for reporting/analytics."""
    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Phishing Tracker"
    }
    try:
        response = requests.get(PHISHING_ATTEMPT_TABLE_URL, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            app.logger.error(f"Backendless All Tracking Fetch Error ({response.status_code}): {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Network error fetching all tracking data: {e}")
        return []

def fetch_all_quiz_results():
    """Fetches ALL quiz results from Backendless for reporting."""
    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Quiz Tracker"
    }
    try:
        response = requests.get(QUIZ_RESULT_TABLE_URL, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            app.logger.error(f"Backendless Quiz Tracking Fetch Error ({response.status_code}): {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Network error fetching quiz tracking data: {e}")
        return []

def log_phishing_attempt(email, password, ip_address, campaign_id=None):
    """Logs the phishing attempt details to a separate table in Backendless."""
    attempt_data = {
        "email": email,
        "password_attempt": password,
        "ip_address": ip_address,
        "campaign_id": campaign_id,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()),
        "status": "Phished"
    }

    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Phishing Logger"
    }
    
    try:
        response = requests.post(PHISHING_ATTEMPT_TABLE_URL, headers=headers, data=json.dumps(attempt_data), timeout=10)
        if response.status_code == 200:
            app.logger.info(f"Phishing attempt logged successfully for: {email} (CID: {campaign_id})")
            return True
        else:
            app.logger.error(f"Backendless Phishing Log Error ({response.status_code}): {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to connect to Backendless for logging phishing attempt: {e}")
        return False

def log_quiz_result(campaign_id, email, score, total_questions):
    """Logs the quiz result details to the new QuizResults table in Backendless."""
    result_data = {
        "campaign_id": campaign_id,
        "email": email,
        "score": score,
        "total_questions": total_questions,
        # Pass criterion: score >= 2 out of 3
        "pass_status": "Pass" if score >= 2 else "Fail", 
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
    }

    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Quiz Logger"
    }
    
    try:
        response = requests.post(QUIZ_RESULT_TABLE_URL, headers=headers, data=json.dumps(result_data), timeout=10)
        if response.status_code == 200:
            app.logger.info(f"Quiz result logged successfully for: {email} (CID: {campaign_id}, Score: {score}/{total_questions})")
            return True
        else:
            app.logger.error(f"Backendless Quiz Log Error ({response.status_code}): {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to connect to Backendless for logging quiz result: {e}")
        return False


# --- Flask Routes ---

@app.route('/')
def home():
    if check_auth():
        return redirect(url_for('admin_dashboard'))
    return render_template('admin.html')

@app.route('/index')
def index_landing():
    # If a user manually accesses /index, redirect them to the generic training page
    return redirect(url_for('training_trap', cid='GENERIC'))

@app.route('/training-trap')
def training_trap():
    campaign_id = request.args.get('cid', 'GENERIC')
    # RENAMED TEMPLATE: Use index.html for the phishing/training flow
    return render_template('index.html', campaign_id=campaign_id, initial_state='form')

@app.route('/phishing-attempt', methods=['POST'])
def phishing_attempt():
    email = request.form.get('email')
    password = request.form.get('password')
    campaign_id = request.form.get('campaign_id')
    ip_address = request.remote_addr

    # Log the successful credential submission (Phishing attempt)
    log_phishing_attempt(email, password, ip_address, campaign_id)

    # RENAMED TEMPLATE: Use index.html for the phishing/training flow
    return render_template('index.html', campaign_id=campaign_id, initial_state='training', submitted_email=email)


@app.route('/log-quiz-result', methods=['POST'])
def api_log_quiz_result():
    """API endpoint to receive quiz results from the client and log them."""
    data = request.get_json()
    
    campaign_id = data.get('campaign_id', 'GENERIC')
    email = data.get('email')
    score = data.get('score')
    total = data.get('total')
    
    if not all([email, score is not None, total is not None]):
        app.logger.error("Missing fields for quiz result logging.")
        return jsonify({"error": "Missing required data"}), 400

    log_quiz_result(campaign_id, email, score, total)
    
    return jsonify({"status": "success", "message": "Quiz results logged successfully."})


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:
        session['logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin.html', error="Invalid Username or Password")


@app.route('/admin')
def admin_dashboard():
    if check_auth():
        campaigns = fetch_all_campaigns()
        return render_template('admin.html', content_type='dashboard', username=HARDCODED_USERNAME, campaigns=campaigns)
    else:
        return redirect(url_for('home'))

@app.route('/add-campaign')
def add_campaign():
    if check_auth():
        return render_template('admin.html', content_type='add_campaign', username=HARDCODED_USERNAME)
    else:
        return redirect(url_for('home'))

@app.route('/delete-campaign/<campaign_id>', methods=['POST'])
def delete_campaign(campaign_id):
    """Deletes a campaign record from Backendless."""
    if not check_auth():
        flash("Unauthorized access.", 'error')
        return redirect(url_for('home'))
    
    headers = {
        "user-agent": "Flask Campaign Deletor"
    }

    try:
        response = requests.delete(f"{BACKENDLESS_BASE_URL}/{campaign_id}", headers=headers, timeout=10)
        
        if response.status_code in [200, 204]:
            flash(f"Campaign with ID {campaign_id} successfully deleted.", 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(f"Error deleting campaign: Backendless returned status {response.status_code}.", 'error')
            return redirect(url_for('admin_dashboard'))

    except requests.exceptions.RequestException as e:
        flash(f"Failed to connect to Backendless for deletion: {e}", 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/analytics')
def analytics_dashboard():
    """Renders the analytics view and provides all necessary data."""
    if not check_auth():
        return redirect(url_for('home'))
    
    campaigns = fetch_all_campaigns()
    all_attempts = fetch_all_phishing_attempts()
    
    return render_template('admin.html', content_type='analytics', username=HARDCODED_USERNAME, campaigns=campaigns, all_attempts=all_attempts)

@app.route('/report')
def report_view():
    """Renders the report view, passing all data sources."""
    if not check_auth():
        return redirect(url_for('home'))
    
    campaigns = fetch_all_campaigns()
    attempts = fetch_all_phishing_attempts()
    quiz_results = fetch_all_quiz_results() 
    
    # Create a map and combine report data for easier template rendering
    campaign_map = {c['objectId']: c['name'] for c in campaigns}
    
    combined_report = []
    
    # 1. Process Phishing Attempts
    for attempt in attempts:
        combined_report.append({
            'id': attempt.get('objectId'),
            'timestamp': attempt.get('timestamp', 'N/A'),
            'email': attempt.get('email', 'N/A'),
            'campaign_id': attempt.get('campaign_id', 'GENERIC'),
            'campaign_name': campaign_map.get(attempt.get('campaign_id'), f"N/A (ID: {attempt.get('campaign_id')})"),
            'type': 'Phishing Attempt',
            'status': 'Credentials Submitted',
            'score': None,
            'total': None
        })
        
    # 2. Process Quiz Results
    for quiz in quiz_results:
        combined_report.append({
            'id': quiz.get('objectId'),
            'timestamp': quiz.get('timestamp', 'N/A'),
            'email': quiz.get('email', 'N/A'),
            'campaign_id': quiz.get('campaign_id', 'GENERIC'),
            'campaign_name': campaign_map.get(quiz.get('campaign_id'), f"N/A (ID: {quiz.get('campaign_id')})"),
            'type': 'Training Result',
            'status': quiz.get('pass_status'),
            'score': quiz.get('score'),
            'total': quiz.get('total_questions')
        })

    # Sort by timestamp (most recent first)
    combined_report.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('admin.html', 
                           content_type='report', 
                           username=HARDCODED_USERNAME, 
                           campaigns=campaigns, 
                           combined_report=combined_report)


@app.route('/export-report/<format>')
def export_report(format):
    """Exports the combined report data to CSV."""
    if not check_auth():
        flash("Unauthorized access.", 'error')
        return redirect(url_for('report_view'))

    # Fetch all data needed for the combined report
    campaigns = fetch_all_campaigns()
    attempts = fetch_all_phishing_attempts()
    quiz_results = fetch_all_quiz_results()
    
    campaign_map = {c['objectId']: c['name'] for c in campaigns}
    
    combined_data = []
    
    # Process Phishing Attempts
    for attempt in attempts:
        combined_data.append({
            'Timestamp': attempt.get('timestamp', 'N/A'),
            'Campaign_Name': campaign_map.get(attempt.get('campaign_id'), f"N/A (ID: {attempt.get('campaign_id')})"),
            'Recipient_Email': attempt.get('email', 'N/A'),
            'Type': 'Phishing Attempt',
            'Status': 'Credentials Submitted',
            'Score': '',
            'Total_Questions': '',
            'IP_Address': attempt.get('ip_address', 'N/A'),
            'Source_ID': attempt.get('objectId')
        })
        
    # Process Quiz Results
    for quiz in quiz_results:
        combined_data.append({
            'Timestamp': quiz.get('timestamp', 'N/A'),
            'Campaign_Name': campaign_map.get(quiz.get('campaign_id'), f"N/A (ID: {quiz.get('campaign_id')})"),
            'Recipient_Email': quiz.get('email', 'N/A'),
            'Type': 'Training Result',
            'Status': quiz.get('pass_status'),
            'Score': quiz.get('score'),
            'Total_Questions': quiz.get('total_questions'),
            'IP_Address': 'N/A (Quiz Log)', 
            'Source_ID': quiz.get('objectId')
        })

    if not combined_data:
        flash("No data to export.", 'error')
        return redirect(url_for('report_view'))

    df = pd.DataFrame(combined_data)

    if format == 'csv':
        csv_data = StringIO()
        # Sort by Timestamp before outputting CSV
        df = df.sort_values(by='Timestamp', ascending=False)
        df.to_csv(csv_data, index=False)
        output = BytesIO(csv_data.getvalue().encode('utf-8'))
        return send_file(output,
                         mimetype='text/csv',
                         download_name='security_report_combined.csv',
                         as_attachment=True)
        
    elif format == 'pdf':
        flash("PDF export is not supported in this demo setup. Use CSV.", 'error')
        return redirect(url_for('report_view'))
        
    else:
        flash("Invalid export format.", 'error')
        return redirect(url_for('report_view'))


@app.route('/api/generate-content', methods=['POST'])
def api_generate_content():
    """Endpoint for generating content preview using Gemini."""
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    campaign_name = data.get('name')
    description = data.get('description')
    method = data.get('method')
    
    if not all([campaign_name, description, method]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Use a dummy ID for preview generation
    generated = generate_content_with_gemini(campaign_name, description, method, campaign_id_for_tracking="PREVIEW")
    
    if "Error" in generated.get('body', ''):
        return jsonify({"error": generated['body']}), 500
        
    return jsonify({
        "subject": generated['subject'],
        "body": generated['body']
    })

@app.route('/api/generate-qr/<code>')
def generate_qr(code):
    """
    This route is no longer used, as QR generation is handled client-side in admin.html.
    It remains here for compatibility but should be ignored.
    """
    return jsonify({"error": "QR Generation now handled client-side."}), 410

@app.route('/api/phishing-attempts/<campaign_id>')
def get_phishing_attempts(campaign_id):
    """Fetches all phishing attempts linked to a specific campaign ID."""
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    where_clause = f"campaign_id='{campaign_id}'"
    query_url = f"{PHISHING_ATTEMPT_TABLE_URL}?where={where_clause}"

    headers = {
        "Content-Type": "application/json",
        "user-agent": "Flask Phishing Tracker"
    }

    try:
        response = requests.get(query_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            app.logger.error(f"Backendless Tracking Fetch Error ({response.status_code}): {response.text}")
            return jsonify({"error": "Failed to fetch tracking data."}), 500
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Network error fetching tracking data: {e}")
        return jsonify({"error": "Network error while fetching tracking data."}), 500


@app.route('/create-campaign', methods=['POST'])
def create_campaign():
    if not check_auth():
        return redirect(url_for('home'))

    # 1. Collect form data
    campaign_name = request.form.get('campaign-name')
    method = request.form.get('method')
    recipients_text = request.form.get('recipients_text')
    campaign_description = request.form.get('campaign-description')
    
    # Use content generated from the preview, if available, otherwise regenerate
    final_body = request.form.get('generated-content-body')
    final_subject = request.form.get('generated-content-subject')

    # Prepare data for Backendless (save initial data to get objectId)
    campaign_data = {
        "name": campaign_name,
        "description": campaign_description,
        "method": method,
        "recipients": recipients_text,
        "schedule": request.form.get('campaign-schedule'),
        "status": "Scheduled",
        "generated_content": "Awaiting content/delivery...",
        "delivery_log": "Awaiting ID generation."
    }

    # 2. SAVE initial campaign to get the objectId (campaign_id)
    headers = { "Content-Type": "application/json", "user-agent": "Flask Campaign Creator" }
    
    try:
        response = requests.post(BACKENDLESS_BASE_URL, headers=headers, data=json.dumps(campaign_data), timeout=10)
        
        if response.status_code != 200:
            flash(f"Backendless Error saving campaign initial data ({response.status_code}): {response.text}", 'error')
            return redirect(url_for('admin_dashboard'))

        saved_campaign = response.json()
        campaign_id = saved_campaign.get('objectId')
        
        # 3. Regenerate/Confirm FINAL content/links using the real campaign_id
        if not final_body or not final_subject:
             final_content = generate_content_with_gemini(campaign_name, campaign_description, method, campaign_id_for_tracking=campaign_id)
             final_body = final_content['body']
             final_subject = final_content['subject']
        else:
             # Content was pre-generated. Now replace the PREVIEW tracking ID with the real one.
             # Note: The tracking URL is now set to /training-trap instead of /index
             final_body = final_body.replace("https://ai-generated-phishing-simulation-for.onrender.com/training-trap?cid=PREVIEW", f"https://ai-generated-phishing-simulation-for.onrender.com/training-trap?cid={campaign_id}")

        tracking_link = f"https://ai-generated-phishing-simulation-for.onrender.com/training-trap?cid={campaign_id}"
        
        # 4. Handle delivery (Email: send to ALL recipients)
        delivery_status = "Not applicable (QR)"
        
        if method == 'email':
            recipient_list = [r.strip() for r in recipients_text.replace(",", "\n").splitlines() if r.strip()]
            
            successful_sends = 0
            if recipient_list:
                for recipient in recipient_list:
                    if send_email(recipient, final_subject, final_body):
                        successful_sends += 1
                
                if successful_sends > 0:
                    delivery_status = f"Successfully sent email to {successful_sends} out of {len(recipient_list)} recipients. Phishing link: {tracking_link}"
                    campaign_data['status'] = "Sent"
                else:
                    delivery_status = f"Email delivery FAILED for all {len(recipient_list)} recipients. Check SMTP credentials or logs."
                    campaign_data['status'] = "Failed"
            else:
                delivery_status = "Email content generated, but no recipients were listed. Email was not sent."
        
        elif method == 'qr':
            delivery_status = f"QR Code link generated: '{tracking_link}'. You can share this link or download the QR image from the admin panel."
            campaign_data['status'] = "Ready"

        # 5. Update data with final content and log
        campaign_data['generated_content'] = final_body
        MAX_CONTENT_LENGTH = 450
        campaign_data['generated_content'] = campaign_data.get('generated_content', "")[:MAX_CONTENT_LENGTH] + ("..." if len(campaign_data.get('generated_content', "")) > MAX_CONTENT_LENGTH else "")
        campaign_data['delivery_log'] = delivery_status
        
        # 6. UPDATE Backendless record
        response = requests.put(f"{BACKENDLESS_BASE_URL}/{campaign_id}", headers=headers, data=json.dumps(campaign_data), timeout=10)
        
        if response.status_code == 200:
            flash(f"Campaign '{campaign_name}' saved and executed. {delivery_status}", 'success')
        else:
            flash(f"Campaign saved initially, but FAILED to update final details ({response.status_code}). Please check log.", 'error')

    except requests.exceptions.RequestException as e:
        flash(f"Failed to connect to Backendless: {e}", 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Use an environment provided PORT (Render / Heroku / many PaaS)
    port = int(os.environ.get('PORT', 5000))
    # Do NOT use debug=True in production; set debug via environment if needed
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)



