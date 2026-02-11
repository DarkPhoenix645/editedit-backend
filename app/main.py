from fastapi import FastAPI

app = FastAPI(
    title="ForensIQ Backend",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {"status": "running", "service": "forensiq-backend"}

@app.get("/health")
async def health():
    return {"status": "ok"}
