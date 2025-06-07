import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")
PLOTS_PATH = os.path.join(PROJECT_ROOT, "output", "plots")
os.makedirs(PLOTS_PATH, exist_ok=True)

# Wczytanie danych
df = pd.read_csv(DATA_PATH)

# Konwersja typów
df["score"] = pd.to_numeric(df["score"], errors="coerce")
df["entropy"] = pd.to_numeric(df["entropy"], errors="coerce")
df["registration_days"] = pd.to_numeric(df["registration_days"], errors="coerce")

print(f"Liczba wszystkich rekordów: {len(df)}")
print(f"Liczba unikalnych domen: {df['domain'].nunique()}\n")

print("Top 10 TLD:")
print(df["tld"].value_counts().head(10), "\n")

print("Top 10 Issuerów:")
print(df["issuer"].value_counts().head(10), "\n")

print("Statystyka entropii:")
print(df["entropy"].describe(), "\n")

print("Domeny z podejrzanymi słowami:")
print(df["has_keyword"].value_counts(), "\n")

print("Domeny z podejrzanym TLD:")
print(df["tld_suspicious"].value_counts(), "\n")

print("Najczęściej dopasowane znane marki:")
print(df["brand_match"].value_counts().head(10), "\n")

grouped = df.groupby(["issuer", "tld_suspicious", "has_keyword"]).size().reset_index(name="count")
print("Kombinacje issuer + TLD podejrzany + słowo kluczowe:")
print(grouped.sort_values("count", ascending=False), "\n")

print("Statystyka phishing score:")
print(df["score"].describe(), "\n")

# Kategoryzacja poziomu ryzyka
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
print("Rozkład poziomu ryzyka:")
print(df["risk_level"].value_counts(), "\n")

# 1. Histogram phishing score
plt.hist(df["score"].dropna(), bins=range(0, 12), edgecolor='black')
plt.title("Rozkład phishing score")
plt.xlabel("Score")
plt.ylabel("Liczba domen")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_distribution.png"))
plt.close()

# 2. Phishing score vs Entropy
sns.scatterplot(data=df, x="entropy", y="score")
plt.title("Phishing score vs Entropy")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_entropy.png"))
plt.close()

# 3. Score vs Registration age
sns.scatterplot(data=df, x="registration_days", y="score")
plt.title("Phishing score vs Wiek domeny (dni)")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_age.png"))
plt.close()

# 4. Histogram długości domen
df["domain_length"] = df["domain"].astype(str).apply(len)
df["domain_length"].hist(bins=20, edgecolor='black')
plt.title("Długość domen")
plt.xlabel("Liczba znaków")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "domain_length.png"))
plt.close()

# 5. Heatmapa TLD vs Issuer
pivot = df.pivot_table(index="tld", columns="issuer", aggfunc="size", fill_value=0)
plt.figure(figsize=(12, 6))
sns.heatmap(pivot, annot=True, fmt="d", cmap="YlGnBu")
plt.title("Częstość: TLD vs Issuer")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "tld_vs_issuer.png"))
plt.close()

# 6. Boxplot score vs brand_match (top 5)
top_brands = df["brand_match"].value_counts().head(5).index
sns.boxplot(data=df[df["brand_match"].isin(top_brands)], x="brand_match", y="score")
plt.title("Phishing score dla najczęstszych brand_match")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_brand_match.png"))
plt.close()

# 7. Score vs słowo kluczowe
sns.boxplot(data=df, x="has_keyword", y="score")
plt.title("Phishing score vs obecność słowa kluczowego")
plt.xticks([0, 1], ["Brak", "Obecne"])
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "score_vs_keyword.png"))
plt.close()

# 8. Wykres słupkowy Top 10 TLD
df["tld"].value_counts().head(10).plot(kind="bar")
plt.title("Top 10 końcówek domen (TLD)")
plt.xlabel("TLD")
plt.ylabel("Liczba")
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_PATH, "top_tld.png"))
plt.close()