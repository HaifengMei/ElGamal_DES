import math
import sys
import json
from base64 import b64encode, b64decode
from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import DES3, DES
from math import sqrt, log

class PrivateKey(object):
	def __init__(self, p=None, g=None, x=None, iNumBits=0):
		self.p = p
		self.g = g
		self.x = x
		self.iNumBits = iNumBits

	def __str__(self):
    		return str(self.__dict__)
		
class PublicKey(object):
	def __init__(self, p=None, g=None, h=None, iNumBits=0):
		self.p = p
		self.g = g
		self.h = h
		self.iNumBits = iNumBits

	def __str__(self):
        	return str(self.__dict__)

# computes the greatest common denominator of a and b.  assumes a > b
def gcd( a, b ):
		while b != 0:
			c = a % b
			a = b
			b = c
		#a is returned if b == 0
		return a

#computes base^exp mod modulus
def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)

#miller_rabin primality test, test if num is prime
def miller_rabin(n, iConfidence):
    if not n > 2:
        raise ValueError

    k = round(log(n, 2)) # determines the accuracy of the test
    s = 0 
    d = n - 1

    while d % 2 == 0:
        s = s + 1
        d = d // 2

    for i in range(iConfidence): # repeat witness loop k times
        a = random.randint(2, n - 2) # pick a random integer a, witness, such that 1 < a < n-1,
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue # Integer x is either prime or a strong liar

        for j in range(s - 1):# check if integer a is a witness for compositness of n
            x = pow(x, 2, n)

            if x == 1:
                return False # n is composite
            elif x == n - 1:
                break # continue witness loop
        else:
            return False

    return True # x is probably prime


#finds a primitive root for prime p
#this function was implemented from the algorithm described here:
#http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
def find_primitive_root( p ):
		if p == 2:
				return 1
		#the prime divisors of p-1 are 2 and (p-1)/2 because
		#p = 2x + 1 where x is a prime
		p1 = 2
		p2 = (p-1) // p1

		#test random g's until one is found that is a primitive root mod p
		while( 1 ):
				g = random.randint( 2, p-1 )
				#g is a primitive root if for all prime factors of p-1
				#g^((p-1)/p[i]) (mod p) is not congruent to 1
				if not (modexp( g, (p-1)//p1, p ) == 1):
						if not modexp( g, (p-1)//p2, p ) == 1:
								return g

#find n bit prime
def find_prime(iNumBits, iConfidence):
		#keep testing until one is found
		while(1):
				#generate potential prime randomly
				p = random.randint( pow(2,(iNumBits-2)), pow(2,(iNumBits-1)) )
				#make sure it is odd
				while( p % 2 == 0 ):
						p = random.randint(pow(2,iNumBits-2),pow(2,iNumBits-1))

				#keep doing this if the miller-rabin test fails
				while( not miller_rabin(p, iConfidence) ):
						p = random.randint( pow(2,iNumBits-2), pow(2,iNumBits-1) )
						while( p % 2 == 0 ):
								p = random.randint(pow(2,iNumBits-2), pow(2,iNumBits-1))

				#if p is prime compute p = 2*p + 1
				#if p is prime, we have succeeded; else, start over
				p = p * 2 + 1
				if miller_rabin(p, iConfidence):
						return p

#encodes bytes to integers mod p.  reads bytes from file
def encodeCustom(sPlaintext, iNumBits):
		byte_array = bytearray(sPlaintext, 'utf-16')

		#z is the array of integers mod p
		z = []

		#each encoded integer will be a linear combination of k message bytes
		#k must be the number of bits in the prime divided by 8 because each
		#message byte is 8 bits long
		k = iNumBits//8

		#j marks the jth encoded integer
		#j will start at 0 but make it -k because j will be incremented during first iteration
		j = -1 * k
		#num is the summation of the message bytes
		num = 0
		#i iterates through byte array
		for i in range( len(byte_array) ):
				#if i is divisible by k, start a new encoded integer
				if i % k == 0:
						j += k
						num = 0
						z.append(0)
				#add the byte multiplied by 2 raised to a multiple of 8
				z[j//k] += byte_array[i]*(pow(2,8*(i%k)))

		#return array of encoded integers
		return z

#decodes integers to the original message bytes
def decodeCustom(aiPlaintext, iNumBits):
		#bytes array will hold the decoded original message bytes
		bytes_array = []

		#same deal as in the encode function.
		#each encoded integer is a linear combination of k message bytes
		#k must be the number of bits in the prime divided by 8 because each
		#message byte is 8 bits long
		k = iNumBits//8

		#num is an integer in list aiPlaintext
		for num in aiPlaintext:
				#get the k message bytes from the integer, i counts from 0 to k-1
				for i in range(k):
						#temporary integer
						temp = num
						#j goes from i+1 to k-1
						for j in range(i+1, k):
								#get remainder from dividing integer by 2^(8*j)
								temp = temp % (pow(2,8*j))
						#message byte representing a letter is equal to temp divided by 2^(8*i)
						letter = temp // (pow(2,8*i))
						#add the message byte letter to the byte array
						bytes_array.append(letter)
						#subtract the letter multiplied by the power of two from num so
						#so the next message byte can be found
						num = num - (letter*(pow(2,8*i)))

		decodedText = bytearray(b for b in bytes_array).decode('utf-16')

		return decodedText

#generates public key K1 (p, g, h) and private key K2 (p, g, x)
def generate_keys(iNumBits=256, iConfidence=32):
		#p is the prime
		#g is the primitve root
		#x is random in (0, p-1) inclusive
		#h = g ^ x mod p
		p = find_prime(iNumBits, iConfidence)
		g = find_primitive_root(p)
		g = modexp( g, 2, p )
		x = random.randint( 1, (p - 1) // 2 )
		h = modexp( g, x, p )

		publicKey = PublicKey(p, g, h, iNumBits)
		privateKey = PrivateKey(p, g, x, iNumBits)

		return {'privateKey': privateKey, 'publicKey': publicKey}


#encrypts a string sPlaintext using the public key k
def encrypt(key, sPlaintext):
		z = encodeCustom(sPlaintext, key.iNumBits)
	#cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
		cipher_pairs = []
		#i is an integer in z
		for i in z:
				#pick random y from (0, p-1) inclusive
				y = random.randint( 0, key.p )
				#c = g^y mod p
				c = modexp( key.g, y, key.p )
				#d = ih^y mod p
				d = (i*modexp( key.h, y, key.p)) % key.p
				#add the pair to the cipher pairs list
				cipher_pairs.append( [c, d] )

		encryptedStr = ""
		for pair in cipher_pairs:
				encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
	
		return encryptedStr

#performs decryption on the cipher pairs found in Cipher using
#private key K2 and writes the decrypted values to file Plaintext
def decrypt(key, cipher):
		#decrpyts each pair and adds the decrypted integer to list of plaintext integers
		plaintext = []

		cipherArray = cipher.split()
		if (not len(cipherArray) % 2 == 0):
				return "Malformed Cipher Text"
		for i in range(0, len(cipherArray), 2):
				#c = first number in pair
				c = int(cipherArray[i])
				#d = second number in pair
				d = int(cipherArray[i+1])

				#s = c^x mod p
				s = modexp( c, key.x, key.p )
				#plaintext integer = ds^-1 mod p
				plain = (d*modexp( s, key.p-2, key.p)) % key.p
				#add plain to list of plaintext integers
				plaintext.append( plain )

		decryptedText = decodeCustom(plaintext, key.iNumBits)

	#remove trailing null bytes
		decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

		return decryptedText

#performs encryption on a byte array plaintext using a key
def DESencrypt(key, plaintext):
	#generate cipher using Cipher FeedBack mode
	cipher = DES.new(key, DES.MODE_CFB)
	#Generate byte array ciphertext
	ct_bytes = cipher.encrypt(plaintext)
	#Encode iv and cipher text byte array to base64 format and translate it into ASCII string formate
	iv = b64encode(cipher.iv).decode('utf-8')
	ct = b64encode(ct_bytes).decode('utf-8')
	#Store iv and ciphertext as JSON
	result = json.dumps({'iv':iv, 'ciphertext':ct})
	#Convert ciphertext JSON object as byte array
	ciphertext = result.encode('utf-8')
	return ciphertext

def DESdecrypt(key, ciphertext):
	#Converted ciphertext byet array back to JSON object
	ciphertextJSON = ciphertext.decode('utf-8')
	#Build python class object from JSON object
	ciphertext = json.loads(ciphertextJSON)
	#Retrieve Base64 iv and ciphertext
	iv_json = ciphertext["iv"]
	ct_json= ciphertext["ciphertext"]
	#Convert Base64 to byte array
	ct = b64decode(ct_json)
	iv = b64decode(iv_json)
	#generate cipher using Cipher FeedBack mode
	cipher= DES.new(key, DES.MODE_CFB, iv = iv)
	plaintext = cipher.decrypt(ct)
	return plaintext

#Encrypts plaintext message using ElGamal approach, a secret key is used to encrypt the private key using DES
def ElGamalDESencrypt(message, key):
	print("\nInitiated ElGamal Encryption....\n")

	#Generate the private and public key
	keys = generate_keys()
	privateKey = keys['privateKey']

	print('Saving secret code to secret.dat ....')
	#Convert key string to byte array
	DESkey = key.encode('utf-8')
	f = open("secret.dat","wb")
	f.write(DESkey)
	f.close()

	print('Encrypting private key...')
	#Convert private key python dictionary object to JSON object
	privateKeyJSON = json.dumps(privateKey.__dict__)
	#Convert JSON private key object to byte array
	privateKeyJSON_bytes = privateKeyJSON.encode('utf-8')
	encryptedPrivateKey = DESencrypt(DESkey, privateKeyJSON_bytes)
	print('Saving encrypted private key to privateKey.dat ....')
	f = open("privateKey.dat","wb")
	f.write(encryptedPrivateKey)
	f.close()

	publicKey = keys['publicKey']
	cipher = encrypt(publicKey, message)
	print('Saving cipher key to cipher.txt ....')
	f = open("cipher.txt","w")
	f.write(cipher)
	f.close()

#Decrypts ciphertext using ElGamal Approach, a secret key is used to decrypt the encrypted private key using DES
def ElGamalDESdecrypt():
	print("\nInitiated ElGamal Decryption....\n")

	
	try:
		print('Locating cipher....')
		f = open("cipher.txt", "r")
	except IOError:
		print('I/O Error: cipher.txt does not exist in the current directory')
		return
	cipher = f.read()
	f.close()

	try:
		print('Locating secret code....')
		f = open("secret.dat", "rb")
	except IOError:
		print('I/O Error: DESkey.dat does not exist in the current directory.')
		return
	DESkey = f.read()
	f.close()

	try:
		print('Locating encrypted private key....')
		f = open("privateKey.dat", "rb")
	except IOError:
		print('I/O Error: privateKey.dat does not exist in the current directory')
		return
	encryptedPrivateKey = f.read()
	f.close()

	print('Decrypting private key')
	decryptedPrivateKey = DESdecrypt(DESkey, encryptedPrivateKey)
	#Converted decrypted private key byte array to JSON object
	privateKeyJSON = decryptedPrivateKey.decode('utf-8')
	#Convert JSON private key object back to python dictionary object
	privateKey = json.loads(privateKeyJSON)

	print('Decrypting cipher....')
	#Rebuild pirvate key python class object using dictionary object 
	privateKey = PrivateKey(p=privateKey["p"], g=privateKey['g'], x=privateKey['x'], iNumBits=privateKey['iNumBits'])
	plain = decrypt(privateKey, cipher)

	print('Decrypted Message: '+plain)

def test():
		assert (sys.version_info >= (3,4))
		print('Select an option')
		print('1. Encrypt Message')
		print('2. Decrypt Message')
		option = int(input())
		if option == 1:
			print('Enter message to be encrypted')
			message = input()
			print('Enter a 8 character secret code')
			key =  input()
			while len(key) != 8:
				print('Key is not 8 characters long, try again')
				key = input()
			ElGamalDESencrypt(message,key)
		else:
			
			ElGamalDESdecrypt()

test()