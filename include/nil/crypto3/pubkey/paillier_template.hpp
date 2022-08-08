//////---------------------------------------------------------------------------//
////// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
////// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
//////
////// MIT License
//////
////// Permission is hereby granted, free of charge, to any person obtaining a copy
////// of this software and associated documentation files (the "Software"), to deal
////// in the Software without restriction, including without limitation the rights
////// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
////// copies of the Software, and to permit persons to whom the Software is
////// furnished to do so, subject to the following conditions:
//////
////// The above copyright notice and this permission notice shall be included in all
////// copies or substantial portions of the Software.
//////
////// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
////// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
////// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
////// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
////// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
////// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
////// SOFTWARE.
//////---------------------------------------------------------------------------//
//
#ifndef CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP
#define CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP

#include "algebraic_operations.hpp"
#include "generating_operations.hpp"

#include <deque>
#include <algorithm>
#include <random>
#include <iostream>
#include <typeinfo>

#include <boost/integer/mod_inverse.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <nil/crypto3/multiprecision/random.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#include <nil/crypto3/multiprecision/miller_rabin.hpp>
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace std;
using namespace nil::crypto3::multiprecision;
using namespace nil::crypto3::algebra;
using namespace boost::math;
using namespace boost::integer;
using cpp_mod = nil::crypto3::multiprecision::cpp_mod;
using cpp_int = nil::crypto3::multiprecision::cpp_int;

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            template<typename FieldType, typename Generator, typename Hash>
            struct paillier_public_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key() {

                }
        
                paillier_public_key(const value_type& n, const value_type& g) :
                    n(n),
                    g(g) {
                }

                paillier_public_key(const paillier_public_key<FieldType, Generator, Hash>& key) {
                    n = key.n;
                    g = key.g;
                }
                
                paillier_public_key& operator=(const paillier_public_key<FieldType, Generator, Hash>& key) {
                    n = key.n;
                    g = key.g;
                    return *this;
                }

                paillier_public_key(paillier_public_key<FieldType, Generator, Hash>&& key) {
                    n = std::move(key.n);
                    g = std::move(key.g);
                }

                paillier_public_key& operator=(paillier_public_key<FieldType, Generator, Hash>&& key) {
                    n = std::move(key.n);
                    g = std::move(key.g);
                    return *this;
                }

                value_type encrypt(value_type& message) {
                    if (message > n) {
                        return value_type(0);
                    }
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    Generator generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(1, n.data.template convert_to<cpp_int>());
                    cpp_int r = distribution(generator);
                    cpp_int first_part = op.pow(g.data.template convert_to<cpp_int>(), message.data.template convert_to<cpp_int>()) *
                        op.pow(r, n.data.template convert_to<cpp_int>());
                    cpp_int second_part = op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2));
                    value_type encrypt_message = value_type(cpp_int(cpp_mod(first_part, second_part)));
                    return encrypt_message;
                  }

                bool verify(cpp_int& s1, cpp_int& s2, value_type& message) {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int value = cpp_int(cpp_mod(op.pow(g.data.template convert_to<cpp_int>(), s1) * op.pow(s2, n.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2))));               

                    digest_type hashed_message = nil::crypto3::hash<Hash>(message.data.template convert_to<cpp_int>().str());
                    string string_hashed_message = to_string(hashed_message);
                    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);

                    if (hash_function_result == value)
                        return true;
                    else
                        return false;
                }
            private:
                value_type n;
                value_type g;
            };

            template<typename FieldType, typename Generator, typename Hash>
            struct paillier_private_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = FieldType::modulus_bits;


                paillier_private_key() {

                }

                paillier_private_key(const paillier_private_key<FieldType, Generator, Hash>& key) {
                    lambda = key.lambda;
                    mu = key.mu;
                    n = key.n;
                    g = key.g;
                }

                paillier_private_key& operator=(const paillier_private_key<FieldType, Generator, Hash>& key) {
                    lambda = key.lambda;
                    mu = key.mu;
                    n = key.n;
                    g = key.g;
                    return *this;
                }

                paillier_private_key(paillier_private_key<FieldType, Generator, Hash>&& key) {
                    lambda = std::move(key.lambda);
                    mu = std::move(key.mu);
                    n = std::move(key.n);
                    g = std::move(key.g);
                }

                paillier_private_key& operator=(paillier_private_key<FieldType, Generator, Hash>&& key) {
                    lambda = std::move(key.lambda);
                    mu = std::move(key.mu);
                    n = std::move(key.n);
                    g = std::move(key.g);
                    return *this;
                }
                                
                paillier_private_key(const value_type& lambda, const value_type& mu, const value_type& n, const value_type& g) :
                    lambda(lambda),
                    mu(mu),
                    n(n),
                    g(g) {
                }

                value_type decrypt(value_type& message) {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    if (message.data.template convert_to<cpp_int>() > op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2))) {
                        return value_type(0);
                    }
                    cpp_int u(cpp_mod(op.pow(message.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2))));
                    cpp_int l_u = (u - 1) / n.data.template convert_to<cpp_int>();
                    value_type decrypt_message = value_type(cpp_int(cpp_mod(l_u * mu.data.template convert_to<cpp_int>(), n.data.template convert_to<cpp_int>())));
                    return decrypt_message;
                }

                pair<cpp_int, cpp_int> sign(value_type& message) {
                    digest_type hashed_message = nil::crypto3::hash<Hash>(message.data.template convert_to<cpp_int>().str());
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    string string_hashed_message = to_string(hashed_message);
                    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);

                    cpp_int numerator = (cpp_int(cpp_mod(op.pow(hash_function_result, lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.template convert_to<cpp_int>();
                    cpp_int denominator = (cpp_int(cpp_mod(op.pow(g.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.template convert_to<cpp_int>();
                    cpp_int s1 = cpp_int(cpp_mod(mod_inverse(denominator, n.data.template convert_to<cpp_int>()) * numerator, n.data.template convert_to<cpp_int>()));

                    cpp_int inverse_n = mod_inverse(n.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>());
                    cpp_int inverse_g = mod_inverse(op.pow(g.data.template convert_to<cpp_int>(), s1), n.data.template convert_to<cpp_int>());
                    cpp_int s2 = cpp_int(cpp_mod(op.pow(hash_function_result * inverse_g, inverse_n), n.data.template convert_to<cpp_int>()));

                    return make_pair(s1, s2);
                }
            private:
                value_type lambda;
                value_type mu;
                value_type n;
                value_type g;
            };

            template<typename FieldType, typename Generator, typename Hash>
            struct paillier {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key<FieldType, Generator, Hash> public_key;
                paillier_private_key<FieldType, Generator, Hash> private_key;

                paillier(const int iterations_number = 20) {
                    primes_generator<FieldType, Generator> generator;
                    primes = generator.generate_primes(iterations_number);
                    n = generate_n();
                    lambda = generate_lambda();
                    g = generate_g();
                    mu = generate_mu();
                    public_key = paillier_public_key<FieldType, Generator, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Generator, Hash>(lambda, mu, n, g);
                }
                paillier(value_type& first_prime, value_type& second_prime) {
                    primes = make_pair(first_prime, second_prime);
                    n = generate_n();
                    lambda = generate_lambda();
                    g = generate_g();
                    mu = generate_mu();
                    public_key = paillier_public_key<FieldType, Generator, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Generator, Hash>(lambda, mu, n);
                }

            private:
                pair<value_type, value_type> primes;
                value_type n;
                value_type g;
                value_type lambda;
                value_type mu;


                value_type generate_n() {
                    return primes.first * primes.second;
                }

                value_type generate_lambda() {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int first = primes.first.data.template convert_to<cpp_int>() - cpp_int(1);
                    cpp_int second = primes.second.data.template convert_to<cpp_int>() - cpp_int(1);
                    cpp_int lcm_result = op.lcm(first, second);
                    return value_type(lcm_result);
                }

                value_type generate_g() {
                    Generator generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(cpp_int(1), n.pow(2).data.template convert_to<cpp_int>());
                    cpp_int value = distribution(generator);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    while (cpp_int(cpp_mod(op.pow(value, lambda.data.template convert_to<cpp_int>()), n.data.template convert_to<cpp_int>())) != cpp_int(1)) {
                        value = distribution(generator);
                    }
                    value_type g(value);
                    return g;
                }

                value_type generate_mu() {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int first_part = op.pow(g.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>());
                    cpp_int second_part = op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2));
                    cpp_int u = cpp_int(cpp_mod(first_part, second_part));
                    cpp_int l_u = (u - 1) / n.data.template convert_to<cpp_int>();
                    value_type mu(mod_inverse(l_u, n.data.template convert_to<cpp_int>()));
                    return mu;
                }

            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP