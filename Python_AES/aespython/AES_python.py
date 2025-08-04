import numpy as np
# AES round işlemleri ve key_schedule içeren modül
from keyschedule.aeskeyschedule import key_schedule, reverse_key_schedule



# method to convert text to unicode matrix
def text2Unicode(text):
  text_matrix = np.zeros((16),dtype=int)  # 16 element vector with zeros

  for i in range(16):
    text_matrix[i] = ord(text[i])     # ord converts char to unicode integer value

  text_matrix = np.reshape(text_matrix,(4,4)) # reshape the vector to a 4x4 matrix
  return text_matrix


# funtion to convert unicode matrix to text
def unicode2Text(matrix):
  text = ""
  matrix = matrix.flatten()
  for i in range(16):
    text+=chr(int(matrix[i])) # chr converts unicode integer to unicode character
  return text


# method to substitute bytes using rjindael s-box
def subBytes(A):
  s_box = np.load('Lookup Tables/s_box.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row, sub_col = A[row,col]//16, A[row,col]%16
      B[row,col] = s_box[sub_row,sub_col]
  return B


# method to restore bytes of using inverse rjindael s-box
def invSubBytes(A):
  inv_s_box = np.load('Lookup Tables/inv_s_box.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row, sub_col = A[row,col]//16, A[row,col]%16
      B[row,col] = inv_s_box[sub_row,sub_col]
  return B


# method to shift rows
def shiftRows(A):
  B = np.zeros((4,4),dtype=int)
  # keep 1st row intact
  B[0,:] = A[0,:]
  # shift each element of 2nd row 1 step to the left 
  B[1,0],B[1,1],B[1,2],B[1,3] = A[1,1],A[1,2],A[1,3],A[1,0] 
  # shift each element of 3rd row 2 steps to the left
  B[2,0],B[2,1],B[2,2],B[2,3] = A[2,2],A[2,3],A[2,0],A[2,1]
  # shift each element of 4th row 3 steps to the left
  B[3,0],B[3,1],B[3,2],B[3,3] = A[3,3],A[3,0],A[3,1],A[3,2]
  return B


# method to restore shifted rows
def invShiftRows(A):
  B = np.zeros((4,4),dtype=int)
  # keep 1st row intact
  B[0,:] = A[0,:]
  # shift each element of 2nd row 1 step to the left 
  B[1,1],B[1,2],B[1,3],B[1,0] = A[1,0],A[1,1],A[1,2],A[1,3] 
  # shift each element of 3rd row 2 steps to the left
  B[2,2],B[2,3],B[2,0],B[2,1] = A[2,0],A[2,1],A[2,2],A[2,3]
  # shift each element of 4th row 3 steps to the left
  B[3,3],B[3,0],B[3,1],B[3,2] = A[3,0],A[3,1],A[3,2],A[3,3]
  return B


#method to mix columns using Galois Field E Table
def mixCol(A):
  e_table = np.load('Lookup Tables/E_Table.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row , sub_col = A[row,col]//16,A[row,col]%16
      B[row,col] = e_table[sub_row,sub_col]
  return B


#method to restore mixed columns using Galois Field L Table
def invMixCol(A):
  l_table = np.load('Lookup Tables/L_Table.npy')
  B = np.zeros((4,4),dtype=int)
  for row in range(4):
    for col in range(4):
      sub_row , sub_col = A[row,col]//16,A[row,col]%16
      B[row,col] = l_table[sub_row,sub_col]
  return B


def addRoundKey(A, key_bytes):
    # 🔧 16-byte round key -> 4x4 numpy matrise dönüştür
    key_matrix = np.array(list(key_bytes), dtype=int).reshape(4, 4)
    return np.bitwise_xor(A, key_matrix)



def removeRoundKey(A, key_bytes):
    key_matrix = np.array(list(key_bytes), dtype=int).reshape(4, 4)
    return np.bitwise_xor(A, key_matrix)



def aesEncrypt(plain_text, key):
    # 🔧 Key'i unicode matrise çevir ve 16-byte düzleştirilmiş olarak key_schedule'e ver
    key_matrix = text2Unicode(key)
    key_bytes = key_matrix.flatten().astype(np.uint8).tobytes()
    round_keys = key_schedule(key_bytes)  # 11 adet 16-byte round key

    length = len(plain_text)
    cipher_text = ""

    # 🔧 16 karakterlik bloklara böl ve son blok eksikse boşlukla tamamla
    plain_text_split = []
    for i in range(length // 16):
        plain_text_split.append(plain_text[16 * i : 16 * (i + 1)])
    if length % 16 != 0:
        last_block = plain_text[16 * (length // 16):]
        last_block += ' ' * (16 - len(last_block))
        plain_text_split.append(last_block)

    for block_idx, sub_string in enumerate(plain_text_split):
        print(f"\n🔐 Şifreleme Bloğu {block_idx + 1}: '{sub_string}'")  # ✅ [EKLENDİ]
        state = text2Unicode(sub_string)

        print(f"  Round  0 Key: {round_keys[0].hex().upper()}")  # ✅ [EKLENDİ]
        state = addRoundKey(state, round_keys[0])

        for round in range(1, 10):
            state = subBytes(state)
            state = shiftRows(state)
            state = mixCol(state)
            print(f"  Round {round:2} Key: {round_keys[round].hex().upper()}")  # ✅ [EKLENDİ]
            state = addRoundKey(state, round_keys[round])

        state = subBytes(state)
        state = shiftRows(state)
        print(f"  Round 10 Key: {round_keys[10].hex().upper()}")  # ✅ [EKLENDİ]
        state = addRoundKey(state, round_keys[10])

        cipher_text += unicode2Text(state)

    return cipher_text


def aesDecrypt(cipher_text, key):
    # 🔧 Key'i unicode matrise çevir ve byte olarak düzleştir
    key_matrix = text2Unicode(key)
    key_bytes = key_matrix.flatten().astype(np.uint8).tobytes()
    round_keys = key_schedule(key_bytes)  # 11 adet round key

    decrypted_text = ""
    length = len(cipher_text)

    # 🔧 16 karakterlik şifreli bloklara ayır
    cipher_text_split = []
    for i in range(length // 16):
        cipher_text_split.append(cipher_text[16 * i : 16 * (i + 1)])

    for block_idx, sub_string in enumerate(cipher_text_split):
        print(f"\n🔓 Deşifreleme Bloğu {block_idx + 1}: '{sub_string}'")  # ✅ [EKLENDİ]
        state = text2Unicode(sub_string)

        print(f"  Round 10 Key: {round_keys[10].hex().upper()}")  # ✅ [EKLENDİ]
        state = removeRoundKey(state, round_keys[10])
        state = invShiftRows(state)
        state = invSubBytes(state)

        for round in range(9, 0, -1):
            print(f"  Round {round:2} Key: {round_keys[round].hex().upper()}")  # ✅ [EKLENDİ]
            state = removeRoundKey(state, round_keys[round])
            state = invMixCol(state)
            state = invShiftRows(state)
            state = invSubBytes(state)

        print(f"  Round  0 Key: {round_keys[0].hex().upper()}")  # ✅ [EKLENDİ]
        state = removeRoundKey(state, round_keys[0])

        decrypted_text += unicode2Text(state)

    return decrypted_text


if __name__== '__main__':
    # 📥 Kullanıcıdan düz metni ve şifreleme anahtarını al
    plain_text = input("Enter a string to be encoded : ")
    cipher_key = input("Enter a 16 character long key for encryption : ")    

    print("\n🔐 Encrypting :")    
    cipher_text = aesEncrypt(plain_text, cipher_key)
    print("\n🧾 The encrypted text is : {}".format(cipher_text))

    # 🔁 Anahtarı tekrar iste, doğrulama için
    user_key = input("\nEnter the key again to decrypt the message: ")

    # 🔄 Şifre çözme anahtarını kontrol et
    if user_key == cipher_key:
        print("\n🔓 Decrypting with provided key:")
        decrypted_text = aesDecrypt(cipher_text, user_key)
        print("\n✅ The decrypted text is : {}".format(decrypted_text))
    else:
        print("\n❌ Error: The provided key does not match. Decryption aborted.")
