# SPN signature scheme
#
# Demonstration of the signature scheme from the paper:
#
# Pavol Zajac: Code-based signature scheme derived from 
#                a MRHS representation of an AES encryption.
#              Central European Conference on Cryptology 2019.
#
# (C) 2019 Pavol Zajac.
#
# Can only be used with explicit e-mail permission of the author :)
# If you own any patents, you are forbiden to even look at this code.


####
# Auxiliary functions
def getP():
  P = matrix(GF(2), 16, 16)
  for i in range(16):
    x = i//4
    y = i%4
    j = 4*y + x
    P[i,j] = 1
  return P

#global matrix (linear layer for SPN)
P = getP()

def getVector(x, l):
  return vector(GF(2), [(x>>i) & 1 for i in range(l-1, -1, -1)]) 

def getVector16(x):
  return getVector(x, 16)

def getVector4(x):
  return getVector(x, 4)

def getInt(v):
  l = len(v)-1
  return sum([int(x)<<(l-e) for (e,x) in enumerate(v)])

####
# Present S-box
SB = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

####
# SPN encryption
def Sbox(v):
  return getVector16(
     SB[getInt(v[0:4])]*0x1000+
     SB[getInt(v[4:8])]*0x100+
     SB[getInt(v[8:12])]*0x10+
     SB[getInt(v[12:16])]*0x1)
  
def encrypt(pt, key):
  s = getVector16(pt)
  k = getVector16(key)
  #round 1: 
  s += k
  print("0x{:04x}".format((getInt(s))))
  s = Sbox(s)
  s = P * s
  #round 2: 
  s += k + getVector16(0x0001)
  print("0x{:04x}".format((getInt(s))))
  s = Sbox(s)
  s = P * s
  #round 3: 
  s += k + getVector16(0x0002)
  print("0x{:04x}".format((getInt(s))))
  s = Sbox(s)
  s = P * s
  #round 4: 
  s += k + getVector16(0x0004)
  print("0x{:04x}".format((getInt(s))))
  s = Sbox(s)
  s += k + getVector16(0x0008)
  print("0x{:04x}".format((getInt(s))))
  return getInt(s)
  
####
# helper function to convert permutation to permutation matrix
# to generate secret key: pi = Permutations(12).random_element()
def getPermutationMatrix(pi):
  A = matrix(GF(2), 64, 64)
  O = matrix(GF(2), 64, 64)
  for x in range(16):
    A[x,x] = 1
  for x in range(16,64):
    b = (x-16)//4
    pib = pi[b] - 1
    y = 16+pib*4 + x%4
    A[x,y] = 1
  return block_matrix(GF(2),[[A,O],[O,A]])  
  
####
# Public key generation
def getPK(key, pi):
  k = getVector16(key)
  v = [0]*16*4 
  v += list(P*(k+ getVector16(0x0001)))
  v += list(P*(k+ getVector16(0x0002)))
  v += list(P*(k+ getVector16(0x0004)))
  v += [0]*16
  
  A = getPermutationMatrix(pi)
  q = vector(GF(2),v)*A
  
  I = identity_matrix(GF(2),16)
  Z = matrix(GF(2),16,16)
  M=block_matrix([ [I,Z,Z,Z, Z,Z,Z,Z], [Z,I,Z,Z, P,Z,Z,Z], [Z,Z,I,Z, Z,P,Z,Z], [Z,Z,Z,I, Z,Z,P,Z], [Z,Z,Z,Z, Z,Z,Z,I]])

  #R1 = random_matrix(GF(2),M.nrows(),M.nrows())
  #piM = R1 * M * A
  piM = M * A
  piHT = LinearCode(piM).dual_code().systematic_generator_matrix().transpose()  
 
  return (q*piHT, piHT)
  
####
# Signature generation (hm = hash(m, r))  
#  - return value contains a copy of hm at the beginning
#  (in real scheme, it should be recomputed from m, r)
def getSignature(hm, key, pi):
  s = getVector16(hm)
  k = getVector16(key)
  result = []
  #round 1:
  result += [getInt(s[0:4]), getInt(s[4:8]), getInt(s[8:12]), getInt(s[12:16])]
  s = Sbox(s)
  s = P * s
  #round 2: 
  s += k + getVector16(0x0001)
  result += [getInt(s[0:4]), getInt(s[4:8]), getInt(s[8:12]), getInt(s[12:16])]
  s = Sbox(s)
  s = P * s
  #round 3: 
  s += k + getVector16(0x0002)
  result += [getInt(s[0:4]), getInt(s[4:8]), getInt(s[8:12]), getInt(s[12:16])]
  s = Sbox(s)
  s = P * s
  #round 4: 
  s += k + getVector16(0x0004)
  result += [getInt(s[0:4]), getInt(s[4:8]), getInt(s[8:12]), getInt(s[12:16])]
  
  newres = result[0:4]+[0]*12
  for x in range(12):
    newres[pi[x]+3] = result[4+x]
    
  return newres
  
####
# Verify that signature is correct
#   - this is true if function returns all zeroes...  
def verify(sig, PK):
  s2 = copy(sig)
  for x in sig:
      s2 += [SB[x]]
  result = []
  for x in s2:
    result += list(getVector4(x))
  v = vector(GF(2), result)
  return v*PK[1] + PK[0]

   