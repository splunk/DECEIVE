import streamlit as st
import json
import base64
import pandas as pd

def is_base64(s):
    """Check if a string is Base64-encoded and decode it if valid."""
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8") if decoded else None
    except (base64.binascii.Error, UnicodeDecodeError):
        return None

def process_logs(file):
    """Reads the file, parses JSON, and decodes Base64 fields if found."""
    logs = []
    for line in file:
        try:
            log_entry = json.loads(line.decode("utf-8").strip())  # Decode and parse JSON
            for key, value in log_entry.items():
                if isinstance(value, str):
                    decoded_value = is_base64(value)
                    if decoded_value:
                        log_entry[key] = f"(Decoded) {decoded_value}"  # Replace with decoded value
            logs.append(log_entry)
        except json.JSONDecodeError as e:
            st.error(f"Error decoding JSON: {e}")
    return logs

def filter_logs(logs, query):
    """Filters logs based on the search query."""
    if not query:
        return logs  # Return all logs if no search query

    return [log for log in logs if any(query.lower() in str(value).lower() for value in log.values())]

def group_by_task_name(logs):
    """Groups logs by session (task name)."""
    grouped_logs = {}
    for log in logs:
        task_name = log.get("task_name", "No Task Name")
        if task_name not in grouped_logs:
            grouped_logs[task_name] = []
        grouped_logs[task_name].append(log)
    return grouped_logs

# Streamlit UI
st.title("SSH Log Viewer with Search, Base64 Decoding & Session Grouping 🔍")

uploaded_file = st.file_uploader("Upload SSH Log JSON file", type=["log", "json"])

if uploaded_file is not None:
    st.success("File uploaded successfully! 📂")
    
    logs = process_logs(uploaded_file)  # Process file and decode Base64
    
    # Search Feature
    search_query = st.text_input("Search logs", placeholder="Enter search keyword (e.g., 'authentication', 'session')")
    
    filtered_logs = filter_logs(logs, search_query)
    
    # Group logs by session
    grouped_logs = group_by_task_name(filtered_logs)

    # Dropdown for selecting a session
    session_options = list(grouped_logs.keys())
    selected_session = st.selectbox("Select a session", session_options)

    # Display selected session logs in a table
    if selected_session:
        session_logs = grouped_logs[selected_session]
        st.subheader(f"Logs for Session: {selected_session}")
        st.dataframe(pd.DataFrame(session_logs))  # Show logs in a table
    else:
        st.warning("No logs found for the selected session.")

else:
    st.info("Please upload a JSON log file to view the logs.")
