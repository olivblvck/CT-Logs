import pandas as pd
import matplotlib.pyplot as plt
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")

# Wczytanie danych
df = pd.read_csv(DATA_PATH)

# Konwersja typów (na wypadek złych danych)
df["score"] = pd.to_numeric(df["score"], errors="coerce")
df["entropy"] = pd.to_numeric(df["entropy"], errors="coerce")

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

# Grupowanie kombinacji issuer + podejrzane cechy
grouped = df.groupby(["issuer", "tld_suspicious", "has_keyword"]).size().reset_index(name="count")
print("Kombinacje issuer + TLD podejrzany + słowo kluczowe:")
print(grouped.sort_values("count", ascending=False), "\n")

# Statystyka phishing score
print("Statystyka phishing score:")
print(df["score"].describe(), "\n")

# Kategoryzacja poziomu zagrożenia
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

# Wykres rozkładu phishing score
plt.hist(df["score"].dropna(), bins=range(0, 12), edgecolor='black')
plt.title("Rozkład phishing score")
plt.xlabel("Score")
plt.ylabel("Liczba domen")
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(PROJECT_ROOT, "output", "score_distribution.png"))
plt.close()