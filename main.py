import streamlit as st
import joblib
import pandas as pd
from feature import FeatureExtractor

st.set_page_config(page_title="ML Phishing Guard", layout="centered")
st.title("Machine Learning Phishing Detector")
st.write("This intelligence model applies an XGBoost model to evaluate 6 parameters of an active URL structure.")

# Load the serialised model
@st.cache_resource
def load_model_pipeline():
    return joblib.load('phishing_pipeline.pkl')

pipeline = load_model_pipeline()

url_input = st.text_input("Enter the active webpage URL to audit:", placeholder="www.example.com")

if st.button("Run Threat Assessment"):
    if url_input:
        with st.spinner("Extracting URL and running predictive inference..."):
            try:
                # Extract the feature dictionary from the input URL
                extractor = FeatureExtractor(url_input)
                
                feature_dict = extractor.getFeaturesDict()

                # Read the feature names from the top-level pipeline asset
                trained_feature_order = pipeline.feature_names_in_.tolist()

                # Align the dictionary values with the training schema order
                aligned_data = {col: feature_dict.get(col, 0) for col in trained_feature_order}
                input_df = pd.DataFrame([aligned_data])

                # Execute predictive inference on the DataFrame
                raw_prediction = pipeline.predict(input_df)
                raw_probability = pipeline.predict_proba(input_df)
                
                # Isolate scalar metrics safely
                final_pred = raw_prediction[0]
                phishing_prob = raw_probability[0][0] * 100
                safe_prob = raw_probability[0][1] * 100

                st.divider()
                if final_pred == 0:
                    st.error(f"🚨 ALERT: High Phishing Probability Detected! ({phishing_prob:.2f}%)")
                    st.warning("This website displays architectural anomalies consistent with phishing website.")
                else:
                    st.success(f"✅ Safe Connection Verified. ({safe_prob:.2f}%)")
                    st.write("The link conforms to standard domain layout guidelines.")
                
                if extractor.soup is None:
                    st.warning("URL is offline. Results may be incorrect.")
                else:
                    st.success(f"Parsed website URL: \n{extractor.parsed_url}")
                
                st.write(" ")
                st.subheader("Live Feature Activation Table")
                st.write("This table displays the real-time scores evaluated by the feature extraction layer:")

                status_mapping = {
                    1: "🟩 Safe / Normal",
                    0: "🟨 Suspicious / Warning",
                    -1: "🟥 Phishing / High Risk"
                }

                audit_rows = []
                for feature_name, raw_value in feature_dict.items():
                    audit_rows.append({
                        "Structural Feature": feature_name,
                        "Score": raw_value,
                        "App Evaluation": status_mapping.get(raw_value, "Unknown")
                    })

                audit_df = pd.DataFrame(audit_rows)
                st.table(audit_df)
                        
            except Exception as e:
                st.error(f"An error occurred during live page execution. Error details: {e}")
    else:
        st.info("Please input a valid target domain string.")