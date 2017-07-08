
test: classicalcipher_test
	./classicalcipher_test

classicalcipher_test: classicalcipher.hh classicalcipher_test.cpp
	clang++ --std=c++11 classicalcipher_test.cpp -o classicalcipher_test

clean:
	rm -f classicalcipher_test
