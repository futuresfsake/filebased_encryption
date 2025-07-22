from Crypto.PublicKey import RSA
import os

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Ensure client directory exists
    os.makedirs("client", exist_ok=True)

    with open("client/private.pem", "wb") as priv_file:
        priv_file.write(private_key)

    with open("client/public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("✅ RSA key pair generated:")
    print("  - client/private.pem")
    print("  - client/public.pem")

if __name__ == "__main__":
    generate_rsa_keypair()
