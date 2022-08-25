//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE pubkey_paillier_test

#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/md5.hpp>

#include "paillier.hpp"

using namespace std;

template <typename value_type>
void check_messages(vector<value_type>& message, vector<cpp_int>& decrypted_message) {
	typedef typename value_type::data_type data_type;
	for (int i = 0; i < message.size(); i++) {
		BOOST_CHECK(message[i].data.template convert_to<cpp_int>() == decrypted_message[i]);
	}
}

template <typename value_type>
vector<value_type> convert_to_value_type(vector<cpp_int>& message) {
	typedef typename value_type::data_type data_type;
	vector<value_type> result;
	for (int i = 0; i < message.size(); i++) {
		result.push_back(value_type(message[i]));
	}
	return result;
}

BOOST_AUTO_TEST_SUITE(paillier_test_suite)

BOOST_AUTO_TEST_CASE(paillier_encrypt_decrypt_test) {
	using field = nil::crypto3::algebra::fields::alt_bn128<254>;
	using value_type = field::value_type;
	using hash = nil::crypto3::hashes::sha2<256>;
	using paillier = nil::crypto3::pubkey::paillier<field, hash>;
	paillier p;
	vector<value_type> message{ value_type(42), value_type(43), value_type(44) };

	vector<cpp_int> encrypted_message = p.public_key.encrypt(message);
	vector<cpp_int> decrypted_message = p.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);

	
	message = vector<value_type>{value_type(1), value_type(2), value_type(3)};
	encrypted_message = p.public_key.encrypt(message);
	decrypted_message = p.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);

	
	message = vector<value_type>{ value_type(4), value_type(5), value_type(6), value_type(7)};
	encrypted_message = p.public_key.encrypt(message);
	decrypted_message = p.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);
}

BOOST_AUTO_TEST_CASE(paillier_encrypt_decrypt_with_different_hashes_test) {
	using field = nil::crypto3::algebra::fields::alt_bn128<254>;
	using value_type = field::value_type;
	using sha256 = nil::crypto3::hashes::sha2<256>;
	using md5 = nil::crypto3::hashes::md5;
	using sha512 = nil::crypto3::hashes::sha2<512>;
	using paillier_sha256 = nil::crypto3::pubkey::paillier<field, sha256>;
	using paillier_sha512 = nil::crypto3::pubkey::paillier<field, sha512>;
	using paillier_md5 = nil::crypto3::pubkey::paillier<field, md5>;
	paillier_sha256 paillier_256;
	vector<value_type> message{ value_type(42), value_type(43), value_type(44) };

	vector<cpp_int> encrypted_message = paillier_256.public_key.encrypt(message);
	vector<cpp_int> decrypted_message = paillier_256.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);


	paillier_sha512 paillier_512;
	encrypted_message = paillier_512.public_key.encrypt(message);
	decrypted_message = paillier_512.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);


	paillier_md5 paillier_md;
	encrypted_message = paillier_md.public_key.encrypt(message);
	decrypted_message = paillier_md.private_key.decrypt(encrypted_message);
	check_messages<value_type>(message, decrypted_message);
}

BOOST_AUTO_TEST_CASE(paillier_sign_verify_test) {
	using field = nil::crypto3::algebra::fields::alt_bn128<254>;
	using value_type = field::value_type;
	using hash = nil::crypto3::hashes::sha2<256>;
	using paillier = nil::crypto3::pubkey::paillier<field, hash>;
	paillier p;
	vector<cpp_int> message{ cpp_int(42), cpp_int(43), cpp_int(44) };

	pair<cpp_int, cpp_int> signs = p.private_key.sign(message);
	vector<value_type> value_type_message = convert_to_value_type<value_type>(message);
	bool verified = p.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(verified);


	message = vector<cpp_int>{ cpp_int(1), cpp_int(2), cpp_int(3) };
	signs = p.private_key.sign(message);
	value_type_message = convert_to_value_type<value_type>(message);
	verified = p.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(verified);


	message = vector<cpp_int>{ cpp_int(4), cpp_int(5), cpp_int(6), cpp_int(7) };
	signs = p.private_key.sign(message);
	message[0] -= 1;
	value_type_message = convert_to_value_type<value_type>(message);
	verified = p.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(!verified);
}

BOOST_AUTO_TEST_CASE(paillier_sign_verify_with_different_hashes_test) {
	using field = nil::crypto3::algebra::fields::alt_bn128<254>;
	using value_type = field::value_type;
	using sha256 = nil::crypto3::hashes::sha2<256>;
	using md5 = nil::crypto3::hashes::md5;
	using sha512 = nil::crypto3::hashes::sha2<512>;
	using paillier_sha256 = nil::crypto3::pubkey::paillier<field, sha256>;
	using paillier_sha512 = nil::crypto3::pubkey::paillier<field, sha512>;
	using paillier_md5 = nil::crypto3::pubkey::paillier<field, md5>;
	paillier_sha256 paillier_256;
	vector<cpp_int> message{ cpp_int(42), cpp_int(43), cpp_int(44) };

	pair<cpp_int, cpp_int> signs = paillier_256.private_key.sign(message);
	vector<value_type> value_type_message = convert_to_value_type<value_type>(message);
	bool verified = paillier_256.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(verified);


	paillier_sha512 paillier_512;
	message = vector<cpp_int>{ cpp_int(1), cpp_int(2), cpp_int(3) };
	signs = paillier_512.private_key.sign(message);
	value_type_message = convert_to_value_type<value_type>(message);
	verified = paillier_512.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(verified);


	paillier_md5 paillier_md;
	message = vector<cpp_int>{ cpp_int(4), cpp_int(5), cpp_int(6), cpp_int(7) };
	signs = paillier_md.private_key.sign(message);
	message[0] -= 1;
	value_type_message = convert_to_value_type<value_type>(message);
	verified = paillier_md.public_key.verify(signs.first, signs.second, value_type_message);
	BOOST_CHECK(!verified);
    
	message[0] += 1;
    value_type_message = convert_to_value_type<value_type>(message);
    verified = paillier_md.public_key.verify(signs.first, signs.second, value_type_message);
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_SUITE_END()