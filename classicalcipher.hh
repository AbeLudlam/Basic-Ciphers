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
#include <iostream>



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
   assert(plaintext.length() > 0);         //Make sure the string has something
   assert(all_letters(plaintext));         // Make sure the string is only letters
   std::string ciphertext;
     //For every letter in the string, Take the int value of the current character, add the key to it, mod(26)   that value, then turn that value back into a character for the ciphertext
   for (char in : plaintext) {           
      char out;        
      out = int_to_char(((char_to_int(in)+_key)%26));     
      ciphertext.push_back(out);
    }
    assert(all_letters(ciphertext));        //Make sure the ciphertext is all letters
    return ciphertext;
  }
  
  virtual std::string decode(const std::string& ciphertext) {
    assert(ciphertext.length() > 0);	//Same as before, make sure there is a string of all letters.
    assert(all_letters(ciphertext));
    std::string plaintext;
    //For decoding, we need to go back to the original value, so we subtract the key and add 26 to avoid negative numbers, then we mod(26), and turn that value back into the original character
    for (char in : ciphertext) {
      char out;
      out = int_to_char(((char_to_int(in)+26-_key)%26));
      plaintext.push_back(out);
    }
    assert(all_letters(plaintext));            //Make sure the plaintext is all letters
    return plaintext;
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
    //Make sure the plaintext exists and is made of all letters
    assert(plaintext.length() > 0);
    assert(all_letters(plaintext));
    std::string ciphertext;
    int count = 0;         //We need the count the number of iterations so that we can repeat the key
    //For every character in the string, we encode the character by adding the int value of the respective    character in the key. The key repeats if the string is longer than it by mod(key.length).
    for (char in : plaintext) {
      char out;
      out = int_to_char(((char_to_int(in)+char_to_int(_key[count% _key.length()]))%26));
	ciphertext.push_back(out);
      count++;               //Count goes up by one so that we can get the next character in the key.
    }
    assert(all_letters(ciphertext));
	
    return ciphertext;
    
  }
  
  virtual std::string decode(const std::string& ciphertext) {
    //Make sure the ciphertexts exists and is made of all letters.
    assert(ciphertext.length() > 0);
    assert(all_letters(ciphertext));
    std::string plaintext;
    int count = 0;
    // To decode the ciphertext, we subtract the integer value of the respective character in the key. We add by 26 to avoid negative values and then mod(26). Then we turn that integer value into the original character.
    for (char in : ciphertext) {
      char out;
      out = int_to_char(((char_to_int(in)+26-char_to_int(_key[count% _key.length()]))%26));
      plaintext.push_back(out);
      count++;                //Same as encode, count goes up to be able to get the next character in key.
    }
    assert(all_letters(plaintext));
    return plaintext;
   
    
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
    //Need a way to put in all the lowercase letters into the playfair table.
    char alphabet[25] = {'a','b','c','d','e','f','g','h','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
    //keep track of the row and columns in the playfair table, and insert acts as boolean for duplicate letters.
    int row = 0;
    int column = 0;
    int insert = 1;
    //Insert each char of the key into the playfair table.
    std::cout << "\n\n" << "Key = " << key << "\n";
    
    for(char in : key)
    {
	//Make sure there are no duplicates by checking the alphabet table for the characters position been replaced with the duplicate symbol ':'
	if(char_to_int(in) <= 8)
	{
		if(alphabet[char_to_int(in)] == ':')
		{
			insert=0;
		}
	}
	else
	{
		if(alphabet[char_to_int(in)-1] == ':')
		{
			insert=0;
		}
	}
	if(insert)
	{
		//insert the current character from the key into the playfair table, and then remove it from the letter table 
    		if(column == 5)
		{
			row++;
			column=0;
			std::cout <<  "\n";
		}
		if(in != 'i')
		{
			table[row][column]= in;
			std::cout << in << " ";
		}
		else
		{
			table[row][column]= 'j';
			std::cout << "j" << " ";
		}
		if(char_to_int(in) <= 8)
		{
			alphabet[char_to_int(in)] = ':';
		}
		else
		{
			alphabet[char_to_int(in)-1] = ':';
		}
		column++;
    	}
	insert=1;
    }
	//fill in the rest of the playfair table with the rest of the alphabet
    for(int x = 0; x < 25 ; x++)
    {
	if(alphabet[x] != ':')
	{
		if(column == 5)
		{
			row++;
			column=0;
			std::cout << "\n" ;
		}
		table[row][column] = alphabet[x];
		std::cout << alphabet[x] << " ";
		column++;
	}
    }
    
	std::cout << "\n";
    
  }

  virtual std::string encode(const std::string& plaintext) {
    assert(plaintext.length() > 0);
    assert(all_letters(plaintext));
    std::string ciphertext;
    //First and second represent the digrims of the plaintext, with firstchar and secondchar values representing their place in the playfair table respectively. Plain is used as regular characters can not be inserted into a const string.
    std::cout << "Plaintext = " << plaintext;
    int first = 0;
    int second = 1;
    int firstchar_row = 0;
    int firstchar_col = 0;
    int secondchar_row = 0;
    int secondchar_col = 0;
    std::string plain = plaintext;
   
    while( first < plain.length())
    {
	//Replace all i's in the plaintext with j's
	if(plain[first] == 'i')
	{
		plain[first] = 'j';
	}
	if(plain[second] == 'i')
	{
		plain[second] = 'j';
	}
	// insert x's at the end of the plaintext if the length of the string for the final digrim is odd
	if(first == plain.length()-1)
	{
		plain.insert(plain.length(), "x");
		
	}
	// insert x's if a digrim is the same character
	if(plain[first] == plain[second])
	{
		plain.insert(second, "x");
		
	}
	//Find the position of the digrims in the playfair table
	while(table[firstchar_row][firstchar_col] != plain[first])
	{
		if(firstchar_col == 5)
		{
			firstchar_col=0;
			firstchar_row++;
		}
		else
		{
			firstchar_col++;
		}
		 
	}
	if(firstchar_col == 5)
	{
		firstchar_col=0;
		firstchar_row++;
	}
	while(table[secondchar_row][secondchar_col] != plain[second])
	{
		if(secondchar_col == 5)
		{
			secondchar_col=0;
			secondchar_row++;
		}
		else
		{
			
			secondchar_col++;
		}
	}
	if(secondchar_col == 5)
	{
		secondchar_col=0;
		secondchar_row++;
	}
	//Check to see if the digrim characters are in the same row, then make the ciphertext the character to the right if they are.
	if(firstchar_row == secondchar_row)
	{
		
		char out1 = table[firstchar_row][(firstchar_col+1)%5];
		char out2 = table[secondchar_row][(secondchar_col+1)%5];
		ciphertext.push_back(out1);
		ciphertext.push_back(out2);
		
	}
	//Check to see if the digrim characters are in the same column, then make the ciphertext the character below them if they are.
	if(firstchar_col == secondchar_col)
	{
		char out1 = table[(firstchar_row+1)%5][firstchar_col];
		char out2 = table[(secondchar_row+1)%5][secondchar_col];
		ciphertext.push_back(out1);
		ciphertext.push_back(out2);
		
	}
	//If the digrim characters are not in the same row and column, make the ciphertext the character on the same row but on the column of the other digrim character 
	if((firstchar_col != secondchar_col) && (firstchar_row != secondchar_row))
	{
		char out1 = table[firstchar_row][secondchar_col];
		char out2 = table[secondchar_row][firstchar_col];
		ciphertext.push_back(out1);
		ciphertext.push_back(out2);
	}
	//Move to the next digrim and reset the search values for the playfair table.
	firstchar_row = 0;
	secondchar_row = 0;
	firstchar_col=0;
	secondchar_col = 0;
	first += 2;
	second += 2;
    }
    std::cout << ",      Ciphertext = " << ciphertext << "\n";
    return ciphertext;
  }
  
  virtual std::string decode(const std::string& ciphertext) { 
    
    assert(ciphertext.length() > 0);
    assert(all_letters(ciphertext));
    std::string plaintext;
    //First and second represent the digrims of the plaintext, with firstchar and secondchar values representing their place in the playfair table respectively. Plain is used as regular characters can not be inserted into a const string.
    std::cout << "\nCiphertext = " << ciphertext;
    int first = 0;
    int second = 1;
    int firstchar_row = 0;
    int firstchar_col = 0;
    int secondchar_row = 0;
    int secondchar_col = 0;
    std::string plain = ciphertext;
   
    while( first < plain.length())
    {
	
	
	//Find the position of the digrims in the playfair table
	while(table[firstchar_row][firstchar_col] != plain[first])
	{
		if(firstchar_col == 5)
		{
			firstchar_col=0;
			firstchar_row++;
		}
		else
		{
			firstchar_col++;
		}
		 
	}
	if(firstchar_col == 5)
	{
		firstchar_col=0;
		firstchar_row++;
	}
	while(table[secondchar_row][secondchar_col] != plain[second])
	{
		if(secondchar_col == 5)
		{
			secondchar_col=0;
			secondchar_row++;
		}
		else
		{
			secondchar_col++;
		}
	}
	if(secondchar_col == 5)
	{
		secondchar_col=0;
		secondchar_row++;
	}
	//Check to see if the digrim characters are in the same row, then make the ciphertext the character to the right if they are.
	if(firstchar_row == secondchar_row)
	{
		
		char out1 = table[firstchar_row][(firstchar_col+1)%5];
		char out2 = table[secondchar_row][(secondchar_col+1)%5];
		plaintext.push_back(out1);
		plaintext.push_back(out2);
		
	}
	//Check to see if the digrim characters are in the same column, then make the ciphertext the character below them if they are.
	if(firstchar_col == secondchar_col)
	{
		char out1 = table[(firstchar_row+1)%5][firstchar_col];
		char out2 = table[(secondchar_row+1)%5][secondchar_col];
		plaintext.push_back(out1);
		plaintext.push_back(out2);
		
	}
	//If the digrim characters are not in the same row and column, make the ciphertext the character on the same row but on the column of the other digrim character 
	if((firstchar_col != secondchar_col) && (firstchar_row != secondchar_row))
	{
		char out1 = table[firstchar_row][secondchar_col];
		char out2 = table[secondchar_row][firstchar_col];
		plaintext.push_back(out1);
		plaintext.push_back(out2);
	}
	//Move to the next digrim and reset the search values for the playfair table.
	firstchar_row = 0;
	secondchar_row = 0;
	firstchar_col=0;
	secondchar_col = 0;
	first += 2;
	second += 2;
    }
    //Delete all the x's from the plaintext
    for( char in: plaintext)
     {    
	if( in == 'x')
	{
		plaintext.erase(char_to_int(in),1);
	}
     }
    std::cout << ",      Plaintext = " << plaintext;
    return plaintext;
  }
  
private:

   char table[5][5];
  
};
