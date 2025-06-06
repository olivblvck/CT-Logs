# dashboard/streamlit_app.py
import streamlit as st
import pandas as pd

st.title("Phishing Domain Monitor")

df = pd.read_csv("data/suspected_phishing.csv")
st.write(df.tail(20))  # ostatnie 20 rekordów

st.line_chart(df["timestamp"].value_counts().sort_index())