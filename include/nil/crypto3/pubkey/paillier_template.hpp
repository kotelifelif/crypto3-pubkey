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
#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#include <nil/crypto3/multiprecision/miller_rabin.hpp>
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>

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

            template<typename FieldType, typename Generator>
            struct paillier_public_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key() {

                }
        
                paillier_public_key(const value_type& n, const value_type& g) :
                    n(n),
                    g(g) {

                }

                paillier_public_key(const paillier_public_key<FieldType, Generator>& key) {
                    n = key.n;
                    g = key.g;
                }
                
                paillier_public_key& operator=(const paillier_public_key<FieldType, Generator>& key) {
                    n = key.n;
                    g = key.g;
                    return *this;
                }

                paillier_public_key(paillier_public_key<FieldType, Generator>&& key) {
                    n = std::move(key.n);
                    g = std::move(key.g);
                }

                paillier_public_key& operator=(paillier_public_key<FieldType, Generator>&& key) {
                    n = std::move(key.n);
                    g = std::move(key.g);
                    return *this;
                }

                value_type encrypt(value_type& message) {
                    Generator generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(1, n.data.template convert_to<cpp_int>());
                    cpp_int r = distribution(generator);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int first_part = op.pow(g.data.template convert_to<cpp_int>(), message.data.template convert_to<cpp_int>()) *
                        op.pow(r, n.data.template convert_to<cpp_int>());
                    cpp_int second_part = op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2));
                    value_type encrypt_message = value_type(cpp_int(cpp_mod(first_part, second_part)));
                    return encrypt_message;
                }

                bool verify() {
                    pair<cpp_int, cpp_int> signs = make_pair(cpp_int(1), cpp_int(1));
                    cpp_int value = cpp_int(cpp_mod(pow(g.data.convert_to<cpp_int>(), signs.first) * pow(signs.second, n.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2))));               
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;

                    std::string message = "42";
                    nil::crypto3::hashes::md5::digest_type d = nil::crypto3::hash<hashes::md5>(message);
                    string d_str = to_string(d);
                    cpp_int hash_function_result = op.hex_to_dec(d_str);

                    if (hash_function_result == value)
                        return true;
                    else
                        return false;
                }
            private:
                value_type n;
                value_type g;
            };

            template<typename FieldType, typename Generator>
            struct paillier_private_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_private_key() {

                }

                paillier_private_key(const paillier_private_key<FieldType, Generator>& key) {
                    lambda = key.lambda;
                    mu = key.mu;
                    n = key.n;
                }

                paillier_private_key& operator=(const paillier_private_key<FieldType, Generator>& key) {
                    lambda = key.lambda;
                    mu = key.mu;
                    n = key.n;
                    return *this;
                }

                paillier_private_key(paillier_private_key<FieldType, Generator>&& key) {
                    lambda = std::move(key.lambda);
                    mu = std::move(key.mu);
                    n = std::move(key.n);
                }

                paillier_private_key& operator=(paillier_private_key<FieldType, Generator>&& key) {
                    lambda = std::move(key.lambda);
                    mu = std::move(key.mu);
                    n = std::move(key.n);
                    return *this;
                }
                                
                paillier_private_key(const value_type& lambda, const value_type& mu, const value_type& n) : 
                    lambda(lambda),
                    mu(mu),
                    n(n) {

                }

                value_type decrypt(value_type& message) {
                    if (message > n.pow(2)) {
                        return value_type(0);
                    }
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int u(cpp_mod(op.pow(message.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2))));
                    cpp_int l_u = (u - 1) / n.data.template convert_to<cpp_int>();
                    value_type decrypt_message = value_type(cpp_int(cpp_mod(l_u * mu.data.template convert_to<cpp_int>(), n.data.template convert_to<cpp_int>())));
                    return decrypt_message;
                }

                pair<cpp_int, cpp_int> sign() {
                    std::string message = "42";
                    nil::crypto3::hashes::md5::digest_type d = nil::crypto3::hash<hashes::md5>(message);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    string d_str = to_string(d);
                    cpp_int hash_function_result = op.hex_to_dec(d_str);

                    cpp_int numerator = (cpp_int(cpp_mod(pow(hash_function_result, lambda.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.convert_to<cpp_int>();
                    cpp_int denominator = (cpp_int(cpp_mod(pow(g.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.convert_to<cpp_int>();
                    cpp_int s1 = cpp_int(cpp_mod(mod_inverse(second_part_s1, n.data.convert_to<cpp_int>()) * numerator, n.data.convert_to<cpp_int>()));

                    cpp_int inverse_n = mod_inverse(n.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>());
                    cpp_int inverse_g = mod_inverse(pow(g.data.convert_to<cpp_int>(), s1), n.data.convert_to<cpp_int>());
                    cpp_int s2 = cpp_int(cpp_mod(pow(hash_function_result * inverse_g, inverse_n), n.data.convert_to<cpp_int>()));

                    return make_pair(s1, s2);
                }
            private:
                value_type lambda;
                value_type mu;
                value_type n;
            };

            template<typename FieldType, typename Generator>
            struct paillier {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key<FieldType, Generator> public_key;
                paillier_private_key<FieldType, Generator> private_key;

                paillier(const int iterations_number = 20) {
                    primes_generator<FieldType, Generator> generator;
                    primes = generator.generate_primes(iterations_number);
                    n = generate_n();
                    lambda = generate_lambda();
                    g = generate_g();
                    mu = generate_mu();
                    public_key = paillier_public_key<FieldType, Generator>(n, g);
                    private_key = paillier_private_key<FieldType, Generator>(lambda, mu, n);
                }
                paillier(value_type& first_prime, value_type& second_prime) {
                    primes = make_pair(first_prime, second_prime);
                    n = generate_n();
                    lambda = generate_lambda();
                    g = generate_g();
                    mu = generate_mu();
                    public_key = paillier_public_key<FieldType, Generator>(n, g);
                    private_key = paillier_private_key<FieldType, Generator>(lambda, mu, n);
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
                    return op.lcm((primes.first - value_type(1)), (primes.second - value_type(1)));
                }

                value_type generate_g() {
                    Generator generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(cpp_int(1), n.pow(2).data.template convert_to<cpp_int>());
                    cpp_int value = distribution(generator);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    while (cpp_int(cpp_mod(op.pow(g.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>()), n.data.template convert_to<cpp_int>())) != cpp_int(1)) {
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