from CryptographyPy import *

str = """ TEST
    string TEST =TEST;
    //std::TEST << (TEST *)TEST << endl;
    return TEST""";
guacamoleCipher = CryptographyPy()
encrypted_text = guacamoleCipher.encryptData(str,"password","salt")
print("encrypted data : ", encrypted_text)
print("-----------------------------------")
print("-----------------------------------")
decrypted_text = guacamoleCipher.decryptData(encrypted_text,"password","salt")
print("decrypted data : ", decrypted_text)
