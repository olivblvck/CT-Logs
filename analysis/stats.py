# analysis/stats.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")
PLOTS_PATH = os.path.join(PROJECT_ROOT, "output", "plots")
os.makedirs(PLOTS_PATH, exist_ok=True)

# Load data
df = pd.read_csv(DATA_PATH)

# Remove exact duplicate rows
df.drop_duplicates(inplace=True)

# Remove likely redundant records based on domain + core features (except timestamp)
df = df.drop_duplicates(subset=[
    "domain", "brand_match", "similarity_score", "issuer", "tld",
    "tld_suspicious", "has_keyword", "entropy", "registration_days", "score"
])

# Convert data types
df["score"] = pd.to_numeric(df["score"], errors="coerce")
df["entropy"] = pd.to_numeric(df["entropy"], errors="coerce")
df["registration_days"] = pd.to_numeric(df["registration_days"], errors="coerce")

# Summary stats
print(f"Total records: {len(df)}")
print(f"Unique domains: {df['domain'].nunique()}\n")

print("Top 10 TLDs:")
print(df["tld"].value_counts().head(10), "\n")

print("Top 10 Issuers:")
print(df["issuer"].value_counts().head(10), "\n")

print("Entropy statistics:")
print(df["entropy"].describe(), "\n")

print("Domains containing suspicious keywords:")
print(df["has_keyword"].value_counts(), "\n")

print("Domains with suspicious TLD:")
print(df["tld_suspicious"].value_counts(), "\n")

print("Most frequent matched brands:")
print(df["brand_match"].value_counts().head(10), "\n")

# Group combinations
grouped = df.groupby(["issuer", "tld_suspicious", "has_keyword"]).size().reset_index(name="count")
print("Issuer + Suspicious TLD + Suspicious keyword combinations:")
print(grouped.sort_values("count", ascending=False), "\n")

# Score stats
print("Phishing score statistics:")
print(df["score"].describe(), "\n")

# Risk labeling
def label_risk(score):
    if pd.isna(score):
        return "unknown"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"

df["risk_level"] = df["score"].apply(label_risk)
print("Risk level distribution:")
print(df["risk_level"].value_counts(), "\n")

# 1. Phishing score distribution
plt.hist(df["score"].dropna(), bins=range(0, 12), edgecolor='black')
plt.title("Phishing Score Distribution")
plt.xlabel("Score")
plt.ylabel("Number of Domains")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_distribution.png"))
plt.close()

# 2. Score vs Entropy
sns.scatterplot(data=df, x="entropy", y="score")
plt.title("Phishing Score vs Entropy")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_entropy.png"))
plt.close()

# 3. Score vs Domain Age
sns.scatterplot(data=df, x="registration_days", y="score")
plt.title("Phishing Score vs Domain Age (days)")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_age.png"))
plt.close()

# 4. Domain length histogram
df["domain_length"] = df["domain"].astype(str).apply(len)
df["domain_length"].hist(bins=20, edgecolor='black')
plt.title("Domain Length Distribution")
plt.xlabel("Number of Characters")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "domain_length.png"))
plt.close()

# 5. Heatmap of TLD vs Issuer
pivot = df.pivot_table(index="tld", columns="issuer", aggfunc="size", fill_value=0)
plt.figure(figsize=(12, 6))
sns.heatmap(pivot, annot=True, fmt="d", cmap="YlGnBu")
plt.title("Frequency: TLD vs Issuer")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "tld_vs_issuer.png"))
plt.close()

# 6. Boxplot: Score by top brand matches
top_brands = df["brand_match"].value_counts().head(5).index
sns.boxplot(data=df[df["brand_match"].isin(top_brands)], x="brand_match", y="score")
plt.title("Phishing Score for Top Brand Matches")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_brand_match.png"))
plt.close()

# 7. Score by suspicious keyword presence
sns.boxplot(data=df, x="has_keyword", y="score")
plt.title("Phishing Score vs Suspicious Keyword Presence")
plt.xticks([0, 1], ["Absent", "Present"])
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_keyword.png"))
plt.close()

# 8. Top 10 TLDs bar chart
df["tld"].value_counts().head(10).plot(kind="bar")
plt.title("Top 10 Domain Endings (TLDs)")
plt.xlabel("TLD")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "top_tld.png"))
plt.close()