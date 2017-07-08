///////////////////////////////////////////////////////////////////////////////
// CSUF CPSC 452, Summer 2017
// Project 1: Classical Ciphers
//
///////////////////////////////////////////////////////////////////////////////

#pragma once

#include <algorithm>
#include <cassert>
#include <cctype>
#include <set>
#include <string>

// If c is a lowercase letter, return its numerical representation,
// where 'a' is 0 and 'z' is 25; otherwise return -1.
inline int char_to_int(char ch) {
  if (islower(ch)) {
    return (ch - 'a');
  } else {
    return -1;
  }
}

// Inverse of char_to_int; assuming x is between 0 and 25 inclusive,
// return the lowercase letter corresponding to x.
inline char int_to_char(int x) {
  assert((x >= 0) && (x <= 25));
  return (x + 'a');
}

// Return true when every character in str is a lowercase letter.
inline bool all_letters(const std::string& str) {
  return all_of(str.begin(), str.end(), islower);
}

// Abstract class for a cipher.
class Cipher {
public:
  // Given a plaintext string of lowercase letters, return the
  // corresponding encrypted ciphertext.
  virtual std::string encode(const std::string& plaintext) const = 0;

  // Given an encrypted ciphertext, return the corresponding decrypted
  // plaintext of lowercase letters.
  virtual std::string decode(const std::string& ciphertext) const = 0;
};

// This is a ridiculously weak cipher that is really only here to show
// you how you could implement the other ciphers. A key is a single
// character; the cipher replaces every occurence of the key with a
// dollar sign $. Decrypting only involves changing the dollar signs
// back to key characters.
class DollarCipher : public Cipher {
public:
  DollarCipher(char key)
    : _key(key) {
    assert(isalpha(key));
  }

  virtual std::string encode(const std::string& plaintext) const {
    // check that the plaintext is legit; it must be a nonempty string
    // of lowercase letters
    assert(plaintext.length() > 0);
    assert(all_letters(plaintext));

    // build the ciphertext one character at a time
    std::string ciphertext;
    for (char in : plaintext) {
      // convert this plaintext character to a ciphertext character
      char out;
      if ( in == _key ) {
	out = '$';
      } else {
	out = in;
      }
      // add the character to the growing ciphertext
      ciphertext.push_back(out);
    }
    return ciphertext;
  }
  
  virtual std::string decode(const std::string& ciphertext) const {
    // Reverse of encode. Note that we don't assert that the
    // ciphertext is all letters, because it probably contains dollar
    // signs too.
    assert(ciphertext.length() > 0);
    std::string plaintext;
    for (char in : ciphertext) {
      char out;
      if ( in == '$' ) {
	out = _key;
      } else {
	out = in;
      }
      plaintext.push_back(out);
    }
    assert(all_letters(plaintext));
    return plaintext;
  }

private:
  char _key;
};

// Caesar cipher with integer shift.
class CaesarCipher {
public:
  // Key must be between 0 and 25 inclusive.
  CaesarCipher(int key)
    : _key(key) {
    assert((key >= 0) && (key <= 25));
  }

  virtual std::string encode(const std::string& plaintext) {
    // TODO rewrite this function and delete this comment
    return "";
  }
  
  virtual std::string decode(const std::string& ciphertext) {
    // TODO rewrite this function and delete this comment
    return "";
  }

private:
  int _key;
};

// Vigenere cipher, NOT using the autokey system.
class VigenereCipher {
public:
  // Key must be all lowercase letters with length at least two.
  VigenereCipher(const std::string& key)
    : _key(key) {
    assert(key.length() >= 2);
    assert(all_letters(key));
  }

  virtual std::string encode(const std::string& plaintext) {
    // TODO rewrite this function and delete this comment
    return "";
  }
  
  virtual std::string decode(const std::string& ciphertext) {
    // TODO rewrite this function and delete this comment
    return "";
  }

private:
  std::string _key;
};

// Playfair cipher, as described in the textbook. When the encoder
// sees an I/J it always uses J.
class PlayfairCipher {
public:
  // Key must be a string of lowercase letters, of length between 1
  // and 25 inclusive.
  PlayfairCipher(const std::string& key) {
    assert(key.length() >= 1);
    assert(key.length() <= 25);
    assert(all_letters(key));

    // TODO write code to initialize your Playfair table data
    // structure, then delete this comment
  }

  virtual std::string encode(const std::string& plaintext) {
    // TODO rewrite this function and delete this comment
    return "";
  }
  
  virtual std::string decode(const std::string& ciphertext) { 
    // TODO rewrite this function and delete this comment
    return "";
  }
  
private:

  // TODO declare variable(s) to store the playfair table, then delete
  // this comment
};
