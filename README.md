# ElGamal DES 

This is a python program designed to perform the following:

Encryption:
* Generate the Elgamal private and public key
* Encrypt private key using DES using Cipher FeedBack, requires 8 bit secret key
* Encrypt message using ElGamal
* Save encrypted private key, cipher, DES key to file

Decryption:
* Load encrypted private key, cipher, DES key from file
* Decrypt encrypted private key using DES and secret key
* Decrypt cipher using ElGamal private key

# Requirements
[PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html)
Pycryptodome is a well maintained drop in replacement of PyCrypto which doesnt have the the overflow vulnerability.

[Python 3.4 and above](https://www.python.org/downloads/)

# Instructions
1. Install PyCrypto

```
pip install -r requirements.txt
```

2. Run the program in root directory of the cloned project
```
python ElGamal.py
``` 

3. Select to perform either encryption of decryption and follow the on screen action
* Expected Encription Output
![El Gamal DES Encryption](https://github.com/HaifengMei/ElGamal_DES/blob/master/Screenshots/ElGamal_DES%20Encryption.PNG?raw=true)

* Expected Decryption Output
![El Gamal DES Decryption](https://github.com/HaifengMei/ElGamal_DES/blob/master/Screenshots/ElGamal_DES%20Decryption.PNG?raw=true)

# [Video Demo](https://drive.google.com/file/d/1DYI_nCNRAbpmiMKeblDYlRziD0wSdXXg/view?usp=sharing)
### Credits
The ElGamal encryption and decryption were based off [RyanRiddle ElGamal](https://github.com/RyanRiddle/elgamal)
