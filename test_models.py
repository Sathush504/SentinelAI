import os
from dotenv import load_dotenv
load_dotenv()
from google import genai
client = genai.Client(api_key=os.getenv('GOOGLE_API_KEY'))
models = ['gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-flash-latest', 'gemini-3.1-flash-lite-preview']
for m in models:
    try:
        print(f"Testing {m}...")
        res = client.models.generate_content(model=m, contents='Hi')
        print(f"Success for {m}")
    except Exception as e:
        print(f"Failed {m}: {str(e)[:100]}")
