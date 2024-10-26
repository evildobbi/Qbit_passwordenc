#!/usr/bin/python3  
import sys  
import hashlib  
import base64  
import uuid  
import argparse  
  
def hash_password(password):  
   salt = uuid.uuid4()  
   salt_bytes = salt.bytes  
   password = str.encode(password)  
   hashed_password = hashlib.pbkdf2_hmac(  
      "sha512", password, salt_bytes, 100000, dklen=64  
   )  
   b64_salt = base64.b64encode(salt_bytes).decode("utf-8")  
   b64_password = base64.b64encode(hashed_password).decode("utf-8")  
   password_string = "{salt}:{password}".format(salt=b64_salt, password=b64_password)  
   return password_string  
  
def verify_password(stored_hash, input_password):  
   salt, stored_hash = stored_hash.split(":")  
   salt_bytes = base64.b64decode(salt)  
   input_password = str.encode(input_password)  
   input_hash = hashlib.pbkdf2_hmac(  
      "sha512", input_password, salt_bytes, 100000, dklen=64  
   )  
   input_hash_b64 = base64.b64encode(input_hash).decode("utf-8")  
   return input_hash_b64 == stored_hash  
  
if __name__ == "__main__":  
   parser = argparse.ArgumentParser(description="Hash and verify passwords")
   parser.add_argument("password", help="Password to hash or verify")
   parser.add_argument("-v", "--verify", help="Verify a password against a stored hash", action="store_true")
   parser.add_argument("-s", "--stored-hash", help="Stored hash to verify against")
   parser.add_argument("-c", "--create", help="Create a new hash for the given password", action="store_true")
   args = parser.parse_args()  
  
   if args.verify:  
      if verify_password(args.stored_hash, args.password):  
        print("Password is valid")  
      else:  
        print("Password is invalid")  
   elif args.create:  
      hashed_password = hash_password(args.password)  
      print(hashed_password)  
   else:  
      print("Error: Must specify either -v or -c option")  
      sys.exit(1)
