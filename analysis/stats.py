import pandas as pd
import matplotlib.pyplot as plt
import os

# Ścieżka do pliku CSV
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CSV_PATH = os.path.join(PROJECT_ROOT, "output", "suspected_phishing.csv")


# Wczytanie danych
df = pd.read_csv(CSV_PATH)

print("🔢 Liczba wszystkich rekordów:", len(df))
print("🔢 Liczba unikalnych domen:", df["domain"].nunique())

# 🌐 TLD
print("\n🌐 Top 10 TLD:")
print(df["tld"].value_counts().head(10))

# 🔐 Issuerzy
print("\n🏢 Top 10 Issuerów:")
print(df["issuer"].value_counts().head(10))

# 🧠 Entropia
print("\n📈 Statystyka entropii:")
print(df["entropy"].describe())

# 📦 Histogram entropii
df["entropy"].plot.hist(bins=30, title="Rozkład entropii domen", figsize=(8,4))
plt.xlabel("Entropia")
plt.tight_layout()
plt.show()

# 💬 Podejrzane słowa
print("\nDomeny z podejrzanymi słowami:")
print(df["has_keyword"].value_counts())

# 🧨 Podejrzane TLD
print("\nDomeny z podejrzanym TLD:")
print(df["tld_suspicious"].value_counts())

# 👤 Najczęściej podobne marki
print("\nNajczęściej dopasowane znane marki:")
print(df["brand_match"].value_counts().head(10))

# 🔗 Korelacja: issuer + podejrzany TLD + słowo kluczowe
print("\nKombinacje issuer + TLD podejrzany + słowo kluczowe:")
combo = df.groupby(["issuer", "tld_suspicious", "has_keyword"]).size().reset_index(name="count")
print(combo.sort_values(by="count", ascending=False).head(15))
