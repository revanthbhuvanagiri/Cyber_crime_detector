import streamlit as st
import json
import re
import os
from ibm_watsonx_ai.foundation_models import Model
import hashlib
import requests
import pandas as pd
from datetime import datetime

# Set up the model
model_id = "ibm/granite-13b-chat-v2"
parameters = {
    "decoding_method": "greedy",
    "max_new_tokens": 900,
    "repetition_penalty": 1.05
}

project_id = os.getenv("PROJECT_ID")
space_id = os.getenv("SPACE_ID")

def get_credentials():
    return {
        "url": "https://us-south.ml.cloud.ibm.com",
        "apikey": "d38ImtKqLpIRMGcIHnbELRc9r4niWjXKHPMDqKbNYrC5"
    }

model = Model(
    model_id=model_id,
    params=parameters,
    credentials=get_credentials(),
    project_id="bcf9d59d-48aa-4aa0-a251-dc010d26afb5",
    space_id=space_id
)

# Incident reporting data storage
INCIDENTS_FILE = "incidents.json"

def load_incidents():
    if os.path.exists(INCIDENTS_FILE):
        with open(INCIDENTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_incidents(incidents):
    with open(INCIDENTS_FILE, 'w') as f:
        json.dump(incidents, f, indent=4)

def report_incident(user_details, suspicious_message, status="Pending"):
    incidents = load_incidents()
    incident = {
        "id": len(incidents) + 1,
        "user_details": user_details,
        "suspicious_message": suspicious_message,
        "status": status,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    incidents.append(incident)
    save_incidents(incidents)

def update_incident_status(incident_id, new_status):
    incidents = load_incidents()
    for incident in incidents:
        if incident["id"] == incident_id:
            incident["status"] = new_status
            break
    save_incidents(incidents)

def generate_email_draft(user_details, original_message):
    email_prompt = f"""Draft a concise email to the Cyber Security Team reporting a potential phishing incident. Include the following details:
    - The user clicked on a suspicious link
    - User-provided details: {user_details}
    - Original suspicious message: {original_message}
    
    The email should be professional, clear, and include recommended next steps for the security team.
    """
    email_draft = model.generate_text(prompt=email_prompt, guardrails=False)
    return email_draft

def main():
    st.set_page_config(page_title="Cyber Security Crime Detector", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ Cyber Security Crime Detector")
    st.markdown("---")
    
    # Initialize session state variables
    if 'question' not in st.session_state:
        st.session_state.question = ""
    if 'analysis_done' not in st.session_state:
        st.session_state.analysis_done = False
    if 'is_scam' not in st.session_state:
        st.session_state.is_scam = None
    if 'response_data' not in st.session_state:
        st.session_state.response_data = None
    if 'generated_response' not in st.session_state:
        st.session_state.generated_response = None
    if 'quiz_score' not in st.session_state:
        st.session_state.quiz_score = 0
    
    tab1, tab2, tab3, tab4 = st.tabs(["Message Analysis", "URL Checker", "Security Quiz", "Incident Dashboard"])
    
    with tab1:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("📧 Enter Suspicious Message")
            st.session_state.question = st.text_area("Paste the suspicious message or email here:", value=st.session_state.question, height=200)
            
            if st.button("🔍 Analyze Message"):
                if st.session_state.question:
                    with st.spinner("Analyzing the message..."):
                        st.session_state.response_data, st.session_state.generated_response = analyze_message(st.session_state.question)
                    st.session_state.analysis_done = True
                    st.session_state.is_scam = st.session_state.response_data.get('is_scam')
            
            if st.session_state.analysis_done:
                st.subheader("🤖 AI Analysis:")
                st.json(st.session_state.generated_response)
                
                if st.session_state.is_scam is not None:
                    if st.session_state.is_scam:
                        st.error("⚠️ Warning: This message has been identified as a potential scam.")
                        clicked = st.radio("Have you already clicked on any links in this message?", ('No', 'Yes'))
                        
                        if clicked == 'Yes':
                            st.warning("🚨 Caution: You may have been exposed to a phishing attempt.")
                            user_details = st.text_area("Please provide details about what happened and what information you may have entered:")
                            
                            if st.button("📧 Generate Email Draft"):
                                with st.spinner("Generating email draft..."):
                                    email_draft = generate_email_draft(user_details, st.session_state.question)
                                st.subheader("📤 Draft Email to Cyber Security Team:")
                                st.text_area("Email Draft:", value=email_draft, height=300)
                                st.info("Please review this draft, make any necessary changes, and send it to your Cyber Security Team.")
                                st.warning("🚨 Contact your IT security team or bank immediately for further assistance.")
                            
                            if st.button("📄 Report Incident"):
                                report_incident(user_details, st.session_state.question)
                                st.success("Incident reported successfully.")
                        else:
                            st.success("✅ Good news: You haven't clicked any links. Here are some tips to protect yourself from phishing:")
                            st.markdown("""
                            1. Always verify the sender's email address
                            2. Be cautious of urgent or threatening language
                            3. Don't click on suspicious links or download attachments
                            4. If unsure, contact the supposed sender through official channels
                            """)
                    else:
                        st.success("✅ This message appears to be legitimate. However, always exercise caution when dealing with sensitive information.")
                else:
                    st.error("❌ Error: Unable to determine if the message is a scam. Please review the AI's response carefully.")
        
        with col2:
            st.subheader("ℹ️ About")
            st.info("""
            This Cyber Security Crime Detector uses AI to analyze messages and emails for potential phishing attempts and other cyber security threats.
            
            Simply paste the suspicious message into the text area and click "Analyze Message" to get an assessment.
            
            Remember: Always be cautious with suspicious messages and never share sensitive information unless you're absolutely sure it's safe.
            """)
            
            st.subheader("🔒 Security Tips")
            st.markdown("""
            - Always verify the sender's email address
            - Be wary of urgent or threatening language
            - Don't click on suspicious links or download attachments
            - Use strong, unique passwords for each account
            - Enable two-factor authentication when possible
            - Keep your software and systems updated
            - Report suspicious activity to your IT department
            """)
    
    with tab2:
        st.subheader("🔗 URL Safety Checker")
        url_to_check = st.text_input("Enter a URL to check:")
        if st.button("Check URL"):
            if url_to_check:
                with st.spinner("Checking URL safety..."):
                    is_safe = check_url_safety(url_to_check)
                if is_safe:
                    st.success(f"✅ The URL {url_to_check} appears to be safe.")
                else:
                    st.error(f"⚠️ The URL {url_to_check} may be unsafe. Exercise caution!")
            else:
                st.warning("Please enter a URL to check.")
    
    with tab3:
        st.subheader("🧠 Cyber Security Quiz")
        questions = generate_security_quiz()
        for i, q in enumerate(questions):
            st.write(f"**Question {i+1}:** {q['question']}")
            user_answer = st.radio(f"Select an answer for question {i+1}:", options=q['options'], key=f"q{i}")
            if st.button(f"Submit Answer {i+1}"):
                if q['options'].index(user_answer) == q['correct']:
                    st.success("Correct!")
                    st.session_state.quiz_score += 1
                else:
                    st.error(f"Incorrect. The correct answer was: {q['options'][q['correct']]}")
        
        st.write(f"Your current score: {st.session_state.quiz_score}/{len(questions)}")
    
    with tab4:
        st.subheader("📊 Incident Reporting Dashboard")
        
        # Load incidents data
        incidents = load_incidents()
        
        if incidents:
            st.write(f"Total Incidents Reported: {len(incidents)}")
            
            # Display incidents in a table
            df = pd.DataFrame(incidents)
            st.dataframe(df)
            
            # Incident status update
            st.subheader("Update Incident Status")
            incident_id = st.number_input("Enter Incident ID to update:", min_value=1)
            new_status = st.selectbox("Select New Status", ["Pending", "In Progress", "Resolved"])
            if st.button("Update Status"):
                update_incident_status(incident_id, new_status)
                st.success(f"Incident {incident_id} status updated to {new_status}.")
            
            # Delete incident
            st.subheader("Delete Incident")
            incident_to_delete = st.number_input("Enter Incident ID to delete:", min_value=1)
            if st.button("Delete Incident"):
                if incident_to_delete > 0 and any(incident["id"] == incident_to_delete for incident in incidents):
                    incidents = [incident for incident in incidents if incident["id"] != incident_to_delete]
                    save_incidents(incidents)
                    st.success(f"Incident {incident_to_delete} deleted successfully.")
                else:
                    st.error(f"Incident ID {incident_to_delete} not found.")
            
            st.markdown("---")

            # Incident statistics
            st.subheader("📈 Incident Statistics")
            if incidents:
                status_counts = pd.DataFrame(pd.Series([incident["status"] for incident in incidents]).value_counts())
                status_counts.columns = ["Count"]
                st.bar_chart(status_counts)
            else:
                st.info("No data available for generating statistics.")

            # Export incidents as CSV
            st.subheader("📥 Export Incidents")
            if incidents:
                csv = pd.DataFrame(incidents).to_csv(index=False)
                st.download_button(
                    label="Download Incidents as CSV",
                    data=csv,
                    file_name='incidents_report.csv',
                    mime='text/csv',
                )
            else:
                st.info("No incidents to export.")
        else:
            st.info("No incidents reported yet.")
