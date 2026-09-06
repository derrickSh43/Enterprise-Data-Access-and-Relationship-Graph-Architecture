"""Interactive human sign-in smoke test; never prints or saves bearer tokens."""
import os
import msal
from eda.db import SessionLocal
from eda.identity_providers import get_identity_provider, map_principal


def main():
    app = msal.PublicClientApplication(os.environ["ENTRA_LOGIN_CLIENT_ID"],
        authority="https://login.microsoftonline.com/" + os.environ["ENTRA_TENANT_ID"])
    flow = app.initiate_device_flow(scopes=[os.environ["ENTRA_LOGIN_SCOPE"]])
    if "user_code" not in flow:
        raise ValueError("Could not start interactive sign-in")
    print(flow["message"], flush=True)
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise ValueError("Sign-in did not issue an access token")
    session = get_identity_provider().verify(result["access_token"])
    with SessionLocal() as db:
        if map_principal(db, session) is None:
            raise ValueError("User not mapped; run inventory sync and check freshness")
    print("PASS: signed-in human maps to the imported Entra user. No resource access granted.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Sign-in check failed ({type(exc).__name__}); check consent, tenant and inventory freshness.")
        raise SystemExit(1) from None
