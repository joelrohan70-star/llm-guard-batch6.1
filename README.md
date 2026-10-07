# LLM Guard PWA

## Deploy on Render
1. Create a GitHub repository.
2. Upload all files/folders from this ZIP.
3. In Render choose New > Web Service and connect the repository.
4. Use the Free plan.
5. Build command: `pip install -r requirements.txt`
6. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`
7. Deploy.
8. Open the HTTPS URL on Android Chrome and choose Install app/Add to Home screen.

BERT and DistilBERT are intentionally shown as Demo Mode until trained model weights are deployed.
