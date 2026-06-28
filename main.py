from fastapi import FastAPI
from pydantic import BaseModel
import jwt
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64, struct

app = FastAPI()

PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY\n"
    "cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID\n"
    "EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc\n"
    "WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW\n"
    "ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI\n"
    "SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX\n"
    "dQIDAQAB\n"
    "-----END PUBLIC KEY-----"
)

ISSUER   = "https://idp.exam.local"
AUDIENCE = "tds-5h0erz4f.apps.exam.local"

# Load the public key object once at startup
public_key = serialization.load_pem_public_key(
    PUBLIC_KEY_PEM.encode(), backend=default_backend()
)

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
def verify_token(body: TokenRequest):
    try:
        claims = jwt.decode(
            body.token,
            public_key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"verify_exp": True}
        )
        aud = claims.get("aud", "")
        # aud can sometimes be a list, convert to string
        if isinstance(aud, list):
            aud = aud[0]
        return {
            "valid": True,
            "email": claims.get("email", ""),
            "sub":   claims.get("sub", ""),
            "aud":   aud,
        }
    except Exception as e:
        print(f"Token rejected: {e}")
        return JSONResponse(status_code=401, content={"valid": False})
