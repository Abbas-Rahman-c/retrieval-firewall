"""Print the model IDs available to your Nebius key, to fill in FIREWALL_MODEL / LLAMA_GUARD_MODEL."""

import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(
    base_url=os.environ.get("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/"),
    api_key=os.environ["NEBIUS_API_KEY"],
)
for m in sorted(client.models.list(), key=lambda m: m.id):
    print(m.id)
