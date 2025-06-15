# analysis/stats.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

# Define paths for data input and output directories
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")
PLOTS_PATH = os.path.join(PROJECT_ROOT, "output", "plots")
os.makedirs(PLOTS_PATH, exist_ok=True)  # Ensure plot directory exists

# Load CSV with detected phishing candidates
df = pd.read_csv(DATA_PATH)

# Remove entries with invalid or missing phishing scores
df = df[df["score"].notna() & (df["score"] >= 0)]

# Drop exact duplicates to avoid overcounting
df.drop_duplicates(inplace=True)

# Further deduplication based on domain + selected features (ignoring timestamp)
df = df.drop_duplicates(subset=[
    "domain", "brand_match", "similarity_score", "issuer", "tld",
    "tld_suspicious", "has_keyword", "entropy", "registration_days", "score"
])

# Convert numeric columns for consistency
df["score"] = pd.to_numeric(df["score"], errors="coerce")
df["entropy"] = pd.to_numeric(df["entropy"], errors="coerce")
df["registration_days"] = pd.to_numeric(df["registration_days"], errors="coerce")

# --- Basic Stats and Summaries ---

print(f"Total records: {len(df)}")
print(f"Unique domains: {df['domain'].nunique()}\n")

# Distribution of top-level domains (TLDs)
print("Top 10 TLDs:")
print(df["tld"].value_counts().head(10), "\n")

# Most frequent certificate issuers
print("Top 10 Issuers:")
print(df["issuer"].value_counts().head(10), "\n")

# Entropy statistics (indicates randomness of domain names)
print("Entropy statistics:")
print(df["entropy"].describe(), "\n")

# Count of domains containing phishing-related keywords
print("Domains containing suspicious keywords:")
print(df["has_keyword"].value_counts(), "\n")

# Count of domains with suspicious TLDs
print("Domains with suspicious TLD:")
print(df["tld_suspicious"].value_counts(), "\n")

# Most common brand names targeted by domain spoofing
print("Most frequent matched brands:")
print(df["brand_match"].value_counts().head(10), "\n")

# Combinations of issuer, suspicious TLD, and keywords
grouped = df.groupby(["issuer", "tld_suspicious", "has_keyword"]).size().reset_index(name="count")
print("Issuer + Suspicious TLD + Suspicious keyword combinations:")
print(grouped.sort_values("count", ascending=False), "\n")

# Overall phishing score distribution
print("Phishing score statistics:")
print(df["score"].describe(), "\n")

# --- Risk Level Labeling ---

# Categorize risk based on phishing score thresholds
def label_risk(score):
    if pd.isna(score):
        return "unknown"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"

# Apply risk level labeling
df["risk_level"] = df["score"].apply(label_risk)
# Show risk level distribution
print("Risk level distribution:")
print(df["risk_level"].value_counts().reindex(["low", "medium", "high"]).fillna(0).astype(int), "\n")


# --- Plots ---

# 1. Distribution of phishing scores
plt.hist(df["score"].dropna(), bins=range(2, 11), edgecolor='black')
plt.title("Phishing Score Distribution")
plt.xlabel("Score")
plt.ylabel("Number of Domains")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_distribution.png"))
plt.close()

# 2. Scatter plot: entropy vs phishing score
sns.scatterplot(data=df, x="entropy", y="score")
plt.title("Phishing Score vs Entropy")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_entropy.png"))
plt.close()

# 3. Scatter plot: domain age vs phishing score
sns.scatterplot(data=df, x="registration_days", y="score")
plt.title("Phishing Score vs Domain Age (days)")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_age.png"))
plt.close()

# 4. Histogram: distribution of domain lengths
df["domain_length"] = df["domain"].astype(str).apply(len)
df["domain_length"].hist(bins=20, edgecolor='black')
plt.title("Domain Length Distribution")
plt.xlabel("Number of Characters")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "domain_length.png"))
plt.close()

# 5. Heatmap: frequency of TLD vs Issuer
pivot = df.pivot_table(index="tld", columns="issuer", aggfunc="size", fill_value=0)
plt.figure(figsize=(12, 6))
sns.heatmap(pivot, annot=True, fmt="d", cmap="YlGnBu")
plt.title("Frequency: TLD vs Issuer")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "tld_vs_issuer.png"))
plt.close()

# 6. Boxplot: phishing score per top brand
top_brands = df["brand_match"].value_counts().head(5).index
sns.boxplot(data=df[df["brand_match"].isin(top_brands)], x="brand_match", y="score")
plt.title("Phishing Score for Top Brand Matches")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_brand_match.png"))
plt.close()

# 7. Boxplot: phishing score vs keyword presence
sns.boxplot(data=df, x="has_keyword", y="score")
plt.title("Phishing Score vs Suspicious Keyword Presence")
plt.xticks([0, 1], ["Absent", "Present"]) if df["has_keyword"].dtype != bool else None
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_keyword.png"))
plt.close()

# 8. Bar chart: top 10 TLDs by frequency
df["tld"].value_counts().head(10).plot(kind="bar")
plt.title("Top 10 Domain Endings (TLDs)")
plt.xlabel("TLD")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "top_tlds.png"))
plt.close()

# 9. Histogram: domain age in days (log scale)
df["registration_days"].hist(bins=60)
plt.yscale("log")
plt.title("Domain Age Distribution (log scale)")
plt.xlabel("Age in days")
plt.ylabel("Count (log)")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "registration_age_log.png"))
plt.close()

# 10. Most common spoofed domain-brand combinations
top_pairs = df.groupby(["domain", "brand_match"]).size().reset_index(name="count")
top_pairs = top_pairs.sort_values("count", ascending=False).head(10)
print("Top spoofed domain-brand combinations:")
print(top_pairs, "\n")

# 11. Boxplot: score distribution by certificate issuer
top_issuers = df["issuer"].value_counts().head(6).index
sns.boxplot(data=df[df["issuer"].isin(top_issuers)], x="issuer", y="score")
plt.title("Score Distribution by Issuer")
plt.xticks(rotation=30)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_issuer.png"))
plt.close()

# Count of domains registered within the last 14 days
print("Domains registered in last 14 days:", (df["registration_days"] < 14).sum())