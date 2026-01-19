from mangum import Mangum

from app.main import app  # FastAPI instance

handler = Mangum(app)

# Testing
