from url_extractor import extract_url_features, FEATURE_NAMES

tests = [
    "https://hdfc.com",
    "https://irctc.co.in",
    "https://zomato.com",
    "https://canva.com",
    "https://notion.so",
    "https://medium.com",
    "https://vercel.com",
    "https://render.com",
    "https://leetcode.com",
    "https://coursera.org",
    "https://udemy.com",
    "https://swiggy.com",
]
print("URL | score | Web_Traffic | Domain_Age | Domain_End | Prefix/Suffix | DNS")
print("-"*90)
for url in tests:
    feats = extract_url_features(url)
    fd = dict(zip(FEATURE_NAMES, feats))
    score = sum(feats)
    print(url, "| score=", score,
          "| traffic=", fd["Web_Traffic"],
          "| age=", fd["Domain_Age"],
          "| end=", fd["Domain_End"],
          "| prefix=", fd["Prefix/Suffix"],
          "| dns=", fd["DNS_Record"])
