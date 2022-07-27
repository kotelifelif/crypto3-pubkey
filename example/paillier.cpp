#include "paillier.hpp"

int main() {
	nil::crypto3::pubkey::generate_primes(5);
	nil::crypto3::pubkey::generate_lambda();
	nil::crypto3::pubkey::generate_g();
	nil::crypto3::pubkey::generate_mu();
	value_type en = nil::crypto3::pubkey::encrypt(value_type(3));
	cout << "en " << en.data << endl;
	value_type de = nil::crypto3::pubkey::decrypt(en);
	cout << "de " << de.data << endl;
}