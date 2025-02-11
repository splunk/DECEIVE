import streamlit as st
import json
import base64

def is_base64(s):
    """Check if a string is Base64-encoded."""
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
            # Scan each key in the log entry to detect Base64-encoded values
            for key, value in log_entry.items():
                if isinstance(value, str):
                    decoded_value = is_base64(value)
                    if decoded_value:
                        log_entry[key] = f"(Decoded) {decoded_value}"  # Replace with decoded value
            logs.append(log_entry)
        except json.JSONDecodeError as e:
            st.error(f"Error decoding JSON: {e}")
    return logs

# Streamlit UI
st.title("SSH Log Viewer with Base64 Decoding 🔍")

uploaded_file = st.file_uploader("Upload SSH Log JSON file", type=["log", "json"])

if uploaded_file is not None:
    st.success("File uploaded successfully! 📂")
    
    logs = process_logs(uploaded_file)  # Process file and decode Base64
    
    # Display logs
    st.subheader("Formatted JSON Logs")
    st.json(logs, expanded=False)  # Show JSON in a collapsible section

    # Table view
    if logs:
        st.subheader("Log Table View")
        st.dataframe(logs)  # Display structured logs in a table

else:
    st.info("Please upload a JSON log file to view the logs.")

