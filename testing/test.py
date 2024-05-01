from CryptographyPy import *

str = """ TEST
    string TEST =TEST;
    //std::TEST << (TEST *)TEST << endl;
    return TEST""";
cryptographyPy = CryptographyPy()
encrypted_text = cryptographyPy.encryptData(str,"password","salt")
print("encrypted data : ", encrypted_text)
print("-----------------------------------")
print("-----------------------------------")
decrypted_text = cryptographyPy.decryptData(encrypted_text,"password","salt")
print("decrypted data : ", decrypted_text)
