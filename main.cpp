#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;


vector<unsigned char> EncryptAES(const vector<unsigned char> &plain, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    vector<unsigned char> cipher(plain.size() + AES_BLOCK_SIZE);
    
    int len = 0;
    int cipherLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), plain.size());
    cipherLen = len;

    EVP_EncryptFinal_ex(ctx, cipher.data() + len, &len);
    cipherLen += len;

    EVP_CIPHER_CTX_free(ctx);

    cipher.resize(cipherLen);

    return cipher;
}


vector<unsigned char> DecryptAES(const vector<unsigned char> &cipher, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    vector<unsigned char> plain(cipher.size());

    int len = 0;
    int plainLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, plain.data(), &len, cipher.data(), cipher.size());
    plainLen = len;

    EVP_DecryptFinal_ex(ctx, plain.data() + len, &len);
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plain.resize(plainLen);

    return plain;
}


void EncryptFile(const string &inputFile, const string &outputFile, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile || !outFile) {
        cerr << "Error opening file!" << endl;
        return;
    }

    vector<unsigned char> plaintext((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    vector<unsigned char> cipher = EncryptAES(plaintext, key, iv);

    string header = "ZUNTIE\n\n";
    outFile.write(header.data(), header.size());

    outFile.write(reinterpret_cast<const char *>(cipher.data()), cipher.size());

    cout << "Encrypted: " << inputFile << " -> " << outputFile << endl;
}


void DecryptFile(const string &inputFile, const string &outputFile, const vector<unsigned char> &key, const vector<unsigned char> &iv) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile || !outFile) {
        cerr << "Error opening file!" << endl;
        return;
    }

    string header(8, '\0');
    inFile.read(&header[0], header.size());

    if (header != "ZUNTIE\n\n") {
        cerr << "Invalid file format!" << endl;
    }

    vector<unsigned char> cipher((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    vector<unsigned char> plain = DecryptAES(cipher, key, iv);

    outFile.write(reinterpret_cast<const char *>(plain.data()), plain.size());

    cout << "Decrypted: " << inputFile << " -> " << outputFile << endl;
}


int main() {
    string inputFile = "script.js";
    string outputFile = "encrypted.js";
    string decryptedFile = "script_dec.js";

    vector<unsigned char> key(32, 0);
    vector<unsigned char> iv(16, 0);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    EncryptFile(inputFile, outputFile, key, iv);
    DecryptFile(outputFile, decryptedFile, key, iv);

    return 0;
}