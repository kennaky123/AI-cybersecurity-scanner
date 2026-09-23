"""Build a balanced, modern phishing dataset combining PhiUSIIL, PhishTank 2026,
and diverse real-world legitimate URLs with realistic deep paths, apex domains,
and trailing slashes (3 slashes: https://domain.com/).
"""

from __future__ import annotations

import random
import re
from pathlib import Path
import zipfile

import pandas as pd

from ml.phishing.features import FEATURE_NAMES, extract_url_features, is_valid_url

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "phishing.csv"
PROCESSED_DATA_PATH = PROJECT_ROOT / "data" / "processed" / "phishing.csv"

PHIUSIIL_CSV = Path(r"C:\Users\chipt\Downloads\dataset\PhiUSIIL_Phishing_URL_Dataset.csv")
PHISHTANK_GZ = Path(r"C:\Users\chipt\Downloads\dataset\verified_online.csv.gz")
TRANCO_ZIP = PROJECT_ROOT / "scratch" / "top-1m.csv.zip"

TOP_SERVICES = [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com",
    "deepseek.com",
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "tiktok.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "spotify.com",
    "reddit.com",
    "wikipedia.org",
    "stackoverflow.com",
    "medium.com",
    "notion.so",
    "dropbox.com",
    "slack.com",
    "zoom.us",
    "cloudflare.com",
    "uci.edu",
    "mit.edu",
    "harvard.edu",
    "stanford.edu",
    "vnexpress.net",
    "tuoitre.vn",
    "dantri.com.vn",
    "zalo.me",
]

REAL_PLATFORM_LEGIT_URLS = [
    # Modern AI services (root with slash, apex, and deep paths)
    "https://chatgpt.com/",
    "https://chatgpt.com",
    "https://chatgpt.com/c/67890abcdef",
    "https://chatgpt.com/g/g-2DQzU5UZl-code-copilot",
    "https://www.chatgpt.com/",
    "https://openai.com/",
    "https://openai.com/index/chatgpt/",
    "https://claude.ai/",
    "https://claude.ai/chat/12345678",
    "https://deepseek.com/",
    # Facebook deep paths, threads, and root with trailing slash (3 slashes)
    "https://www.facebook.com/",
    "https://facebook.com/",
    "https://www.facebook.com/messages/t/3426561450703929",
    "https://www.facebook.com/messages/t/1000849204918234",
    "https://www.facebook.com/groups/1429810481029481/permalink/2940184019284019/",
    "https://www.facebook.com/events/849204819204819/",
    "https://www.facebook.com/photo.php?fbid=987654321098765&set=a.123456789012345&type=3",
    "https://www.facebook.com/profile.php?id=100092837465019",
    "https://m.facebook.com/story.php?story_fbid=789123456789123&id=100012345678912",
    # YouTube video, shorts, playlist, and root with trailing slash
    "https://www.youtube.com/",
    "https://youtube.com/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/watch?v=jNQXAC9IVRw&t=42s",
    "https://www.youtube.com/shorts/5v2j7_mE40M",
    "https://www.youtube.com/playlist?list=PLrAXtmErZgOdP_8GztsuKi9nv81odV448",
    "https://www.youtube.com/@Veritasium/videos",
    "https://www.youtube.com/channel/UC6nSFpj9HTCZ5t-N3Rm3-HA",
    # Academic and research links
    "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
    "https://archive.ics.uci.edu/dataset/327/phishing+websites",
    "https://arxiv.org/abs/2301.00000",
    "https://arxiv.org/pdf/2402.12345v1.pdf",
    "https://doi.org/10.1145/3548606.3560645",
    "https://sciencedirect.com/science/article/pii/S187705092301234X",
    # Developer, documentation and cloud URLs
    "https://github.com/",
    "https://github.com",
    "https://github.com/FutureComputing4AI/EMBER2024",
    "https://github.com/microsoft/LightGBM/releases/tag/v4.3.0",
    "https://github.com/pandas-dev/pandas/issues/57891",
    "https://docs.python.org/3/library/argparse.html#module-argparse",
    "https://docs.python.org/3/tutorial/datastructures.html",
    "https://cloud.google.com/vertex-ai/docs/start/introduction-unified-platform",
    "https://learn.microsoft.com/en-us/azure/machine-learning/overview-what-is-azure-machine-learning",
    "https://huggingface.co/datasets/PhiUSIIL/phishing-urls",
    # Wikipedia and knowledge articles
    "https://en.wikipedia.org/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/LightGBM",
    "https://en.wikipedia.org/wiki/Portable_Executable",
    "https://vi.wikipedia.org/wiki/Tr%C3%AD_tu%E1%BB%87_nh%C3%A2n_t%E1%BA%A1o",
]

PATH_TEMPLATES = [
    "/articles/{year}/{month:02d}/{slug}-{id}.html",
    "/product/{slug}-{id}?ref=search&category={cat}",
    "/news/{cat}/{year}/{slug}.php",
    "/blog/posts/{year}/{slug}?page={page}",
    "/docs/{version}/getting-started/{slug}.html",
    "/category/{cat}/{slug}/page/{page}",
    "/item/detail/{id}?variant={cat}&ref=top",
    "/view/story/{id}/{slug}",
    "/wiki/{slug}_{cat}",
    "/forum/threads/{slug}.{id}/page-{page}",
]

SAMPLE_SLUGS = [
    "deep-learning-architecture-overview",
    "cybersecurity-best-practices-2026",
    "high-performance-computing-systems",
    "artificial-intelligence-in-healthcare",
    "sustainable-cloud-infrastructure",
    "enterprise-software-deployment-guide",
    "open-source-community-updates",
    "next-generation-web-technologies",
    "data-privacy-and-compliance-regulations",
    "modern-operating-system-internals",
]

SAMPLE_CATS = ["technology", "research", "business", "security", "engineering", "education", "science"]


def generate_legit_urls(tranco_domains: list[str], count: int = 15000, seed: int = 42) -> list[str]:
    rng = random.Random(seed)
    urls = list(REAL_PLATFORM_LEGIT_URLS)
    
    # Repeat the critical platform links to ensure strong representation in trees
    for _ in range(30):
        urls.extend(REAL_PLATFORM_LEGIT_URLS)

    # Add popular top services in both root forms (with '/' and without '/')
    for s in TOP_SERVICES:
        urls.append(f"https://{s}/")
        urls.append(f"https://{s}")
        urls.append(f"https://www.{s}/")
        urls.append(f"https://www.{s}")

    # Generate root domains from Tranco with trailing slashes (num_slashes=3, path_length=1)
    # and apex domains without www (num_subdomains=0)
    for domain in tranco_domains[:2500]:
        urls.append(f"https://{domain}/")  # 3 slashes, apex domain!
        urls.append(f"https://{domain}")   # 2 slashes, apex domain!
        urls.append(f"https://www.{domain}/")  # 3 slashes, www domain!

    while len(urls) < count:
        domain = rng.choice(tranco_domains)
        template = rng.choice(PATH_TEMPLATES)
        slug = rng.choice(SAMPLE_SLUGS)
        cat = rng.choice(SAMPLE_CATS)
        year = rng.randint(2020, 2026)
        month = rng.randint(1, 12)
        item_id = rng.randint(100000, 99999999)
        page = rng.randint(1, 20)
        version = f"v{rng.randint(1, 5)}.{rng.randint(0, 9)}"

        path = template.format(
            year=year,
            month=month,
            slug=slug,
            id=item_id,
            cat=cat,
            page=page,
            version=version,
        )
        url = f"https://{domain}{path}"
        urls.append(url)
    return urls[:count]


def augment_phi_legit(phi_urls: list[str], seed: int = 42) -> list[str]:
    """Augment PhiUSIIL legitimate URLs to remove spurious www and trailing slash bias."""
    rng = random.Random(seed)
    augmented: list[str] = []
    for u in phi_urls:
        url = u.strip()
        # In PhiUSIIL, all urls start with https://www.
        has_www = "://www." in url
        has_trailing_slash = url.endswith("/")

        mode = rng.random()
        if mode < 0.35 and has_www:
            # Convert to apex domain (num_subdomains = 0)
            url = url.replace("://www.", "://")
        elif mode < 0.70 and not has_trailing_slash:
            # Append trailing slash (num_slashes = 3, path_length = 1)
            url = url + "/"
        elif mode < 0.85 and has_www and not has_trailing_slash:
            # Both: apex domain and trailing slash
            url = url.replace("://www.", "://") + "/"

        augmented.append(url)
    return augmented


def main() -> None:
    print("[1/5] Loading Tranco top domains...")
    tranco_domains: list[str] = []
    if TRANCO_ZIP.is_file():
        with zipfile.ZipFile(TRANCO_ZIP) as z:
            with z.open("top-1m.csv") as f:
                df_tranco = pd.read_csv(f, header=None, nrows=5000)
                tranco_domains = df_tranco[1].dropna().tolist()
    if not tranco_domains:
        tranco_domains = ["google.com", "facebook.com", "youtube.com", "microsoft.com", "apple.com", "github.com"]

    print(f"Loaded {len(tranco_domains)} top domains.")

    print("[2/5] Generating diverse legitimate URLs (including apex domains and trailing slashes)...")
    deep_legit = generate_legit_urls(tranco_domains, count=15000)

    print("[3/5] Loading PhiUSIIL dataset...")
    df_phi = pd.read_csv(PHIUSIIL_CSV, usecols=["URL", "label"])
    # PhiUSIIL: 1 = Legitimate, 0 = Phishing
    raw_phi_legit = df_phi[df_phi["label"] == 1]["URL"].dropna().sample(n=15000, random_state=42).tolist()
    phi_legit = augment_phi_legit(raw_phi_legit)
    phi_phish = df_phi[df_phi["label"] == 0]["URL"].dropna().sample(n=15000, random_state=42).tolist()

    print("[4/5] Loading PhishTank 2026 verified phishing URLs...")
    df_pt = pd.read_csv(PHISHTANK_GZ, usecols=["url", "online"])
    pt_phish = df_pt[df_pt["online"].astype(str).str.lower() == "yes"]["url"].dropna().sample(n=15000, random_state=42).tolist()

    all_legit = deep_legit + phi_legit
    all_phish = phi_phish + pt_phish

    print(f"Total Legit: {len(all_legit)} | Total Phish: {len(all_phish)}")

    legit_df = pd.DataFrame({"url": all_legit, "label": 0})
    phish_df = pd.DataFrame({"url": all_phish, "label": 1})

    combined = pd.concat([legit_df, phish_df], ignore_index=True)
    combined = combined.drop_duplicates(subset=["url"]).reset_index(drop=True)
    
    # Filter valid URLs
    valid_mask = combined["url"].map(is_valid_url)
    combined = combined.loc[valid_mask].reset_index(drop=True)

    RAW_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(RAW_DATA_PATH, index=False)
    print(f"Saved raw dataset ({len(combined)} rows) to: {RAW_DATA_PATH}")

    print("[5/5] Extracting offline lexical features for processed dataset...")
    feature_rows = [extract_url_features(url) for url in combined["url"]]
    processed = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    processed["label"] = combined["label"].to_numpy()

    PROCESSED_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    processed.to_csv(PROCESSED_DATA_PATH, index=False)
    print(f"Saved processed dataset ({len(processed)} rows) to: {PROCESSED_DATA_PATH}")
    print(f"Legitimate count: {(processed['label'] == 0).sum()}")
    print(f"Phishing count:   {(processed['label'] == 1).sum()}")


if __name__ == "__main__":
    main()
