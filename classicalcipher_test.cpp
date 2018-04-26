
#include <iostream>
#include <string>

#include "classicalcipher.hh"

int total_points = 0;
bool all_passed = true;

class TestFailedException {
public:
  TestFailedException(int line,
		      const std::string file,
		      const std::string& message)
    : _line(line), _file(file), _message(message) { }

  int line() const { return _line; }
  const std::string& file() const { return _file; }
  const std::string& message() const { return _message; }

private:
  int _line;
  const std::string _file, _message;
};    

#define TEST(message, expr) { if ( ! (expr) ) throw TestFailedException(__LINE__, __FILE__, std::string(message)); }

class RubricItem {
public:
  RubricItem(const std::string& name, int points)
    : _name(name), _points(points) { }

  virtual void tests() = 0;

  void run() {
    std::cout << _name << ": ";
    bool crash = false;
    try {
      tests();
    } catch (TestFailedException e) {
      crash = true;
      std::cout << std::endl
		<< "    TEST FAILED: " << std::endl
		<< "    line " << e.line()
		<< " of file " << e.file()
		<< ", message: " << e.message()
	        << std::endl
		<< "    score 0/" << _points
		<< std::endl;
      all_passed = false;
    }

    if (!crash) {
      std::cout << "passed, score "
		<< _points << "/" << _points
		<< std::endl;
      total_points += _points;
    }
  }
  
private:
  std::string _name;
  int _points;
};

const std::string LONG_PLAINTEXT = "computerscienceisnomoreaboutcomputersthanastronomyisabouttelescopes";

class DollarCipherItem : public RubricItem {
public:
  DollarCipherItem() : RubricItem("Dollar cipher still works", 3) { }

  void tests() {
    DollarCipher c('a');
    TEST("never use key", c.encode("letters") == "letters");
    TEST("use key once", c.encode("star") == "st$r");
    TEST("use key twice", c.encode("anna") == "$nn$");
    TEST("all keys", c.encode("aaaa") == "$$$$");
    TEST("round trip", c.decode(c.encode(LONG_PLAINTEXT)) == LONG_PLAINTEXT);
  }
};

class CaesarCipherItem : public RubricItem {
public:
  CaesarCipherItem() : RubricItem("Caesar cipher", 1) { }

  void tests() {
    CaesarCipher c1(3);
    TEST("textbook example", c1.encode("meetmeafterthetogaparty") == "phhwphdiwhuwkhwrjdsduwb");
    CaesarCipher c2(23);
    TEST("Wikipedia first example", c2.encode("abcdefghijklmnopqrstuvwxyz") == "xyzabcdefghijklmnopqrstuvw");
    TEST("Wikipedia second example", c2.encode("thequickbrownfoxjumpsoverthelazydog") == "qebnrfzhyoltkclugrjmplsboqebixwvald");
    CaesarCipher c3(17);
    TEST("round trip", c3.decode(c3.encode(LONG_PLAINTEXT)) == LONG_PLAINTEXT);
  }
};

class VigenereCipherItem : public RubricItem {
public:
  VigenereCipherItem() : RubricItem("Vigenere cipher", 1) { }

  void tests() {
    VigenereCipher c1("deceptive");
    TEST("textbook example encode", c1.encode("wearediscoveredsaveyourself") == "zicvtwqngrzgvtwavzhcqyglmgj");
    TEST("textbook example decode", c1.decode("zicvtwqngrzgvtwavzhcqyglmgj") == "wearediscoveredsaveyourself");
    VigenereCipher c2("lemon");
    TEST("Wikipedia example encode", c2.encode("attackatdawn") == "lxfopvefrnhr");
    TEST("Wikipedia example decode", c2.decode(c2.encode("attackatdawn")) == "attackatdawn");
    VigenereCipher c3("platypus");
    TEST("round trip", c3.decode(c3.encode(LONG_PLAINTEXT)) == LONG_PLAINTEXT);
  }
};

class PlayfairCipherItem : public RubricItem {
public:
  PlayfairCipherItem() : RubricItem("Playfair cipher", 1) { }

  void tests() {
    PlayfairCipher c1("monarchy");
    TEST("convert Is to Js", c1.encode("bi") == "js");
    TEST("textbook example part 2", c1.encode("ar") == "rm");
    TEST("textbook example part 3", c1.encode("mu") == "cm");
    TEST("textbook example part 4", c1.encode("hsea") == "bpjm");
    TEST("add Xs between repeated letters", c1.encode("balloon") == "jbsupmna");
    TEST("pad odd-length plaintext with x", c1.encode("dog") == "hrjw");
    TEST("pad length-1 plaintext with x", c1.encode("d") == "bz");
    TEST("monarchy platypus", c1.encode("platypus") == "qprshqxl");
    TEST("monarchy long plaintext", c1.encode(LONG_PLAINTEXT) == "hmolzlkmlbkfmyfkqanonmjmhazlhmolzlkmtlboartlmnanncsxbjmvszlkullbhvjl");

    PlayfairCipher c2("icarus");
    TEST("icarus dogs", c2.encode("dogs") == "bpng");
    TEST("icarus platypus", c2.encode("platypus") == "qkupxqjf");
    TEST("icarus togaparty", c2.encode("togaparty") == "npkjxduqzy");
    TEST("icarus long plaintext", c2.encode(LONG_PLAINTEXT) == "bwktfzlebjrsojsrgvthqcdrhwfzbwktfzlefnkcpjfncqoplzsgcdtcpzqfqlbjpqfb");
  }
};

int main() {
  {
    DollarCipherItem item;
    item.run();
  }

  {
    CaesarCipherItem item;
    item.run();
  }

  {
    VigenereCipherItem item;
    item.run();
  }

  {
    PlayfairCipherItem item;
    item.run();
  }

  std::cout << std::endl
	    << "TOTAL SCORE = " << total_points << "/" << 6
	    << std::endl << std::endl;
  
  if (all_passed) {
    return 0;
  } else {
    return 1;
  }
}
