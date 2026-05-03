import pandas as pd

malicious = pd.read_csv("output/malware.csv")
benign = pd.read_csv("output/benign.csv")

malicious["label"] = 1
benign["label"] = 0

df = pd.concat([malicious, benign], ignore_index=True)
df = df.sample(frac=1, random_state=42) 
df.to_csv("output/features.csv", index=False)

print(f"Malicious: {len(malicious)}, Benign: {len(benign)}, Total: {len(df)}")
print(f"Failed parses not included (returned None and were skipped)")
print(f"Malicious: {len(malicious)}, Benign: {len(benign)}, Total: {len(df)}")
print(f"Class balance: {df['label'].value_counts().to_dict()}")
