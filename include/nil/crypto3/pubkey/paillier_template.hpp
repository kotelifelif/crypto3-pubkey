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
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key(const value_type& n, const value_type& g) :
                    n(n),
                    g(g) {

                }

                //value_type encrypt(value_type& message) {
                //    Generator generator(time(0));
                //    boost::random::uniform_int_distribution<cpp_int> distribution(1, n.data.convert_to<cpp_int>());
                //    cpp_int r = distribution(generator);
                //    cpp_int first_part = pow(g.data.convert_to<cpp_int>(), message.data.convert_to<cpp_int>()) *
                //        pow(r, n.data.convert_to<cpp_int>());
                //    cpp_int second_part = pow(n.data.convert_to<cpp_int>(), cpp_int(2));
                //    value_type encrypt_message = value_type(cpp_int(cpp_mod(first_part, second_part)));
                //    return encrypt_message;
                //}
            private:
                value_type n;
                value_type g;
            };

            template<typename FieldType, typename Generator>
            struct paillier_private_key {
                typedef typename FieldType::value_type value_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_private_key(const value_type& lambda, const value_type& mu, const value_type& n) : 
                    lambda(lambda),
                    mu(mu),
                    n(n) {

                }

                //value_type decrypt(value_type& message) {
                //    if (message > n.pow(2)) {
                //        return value_type(0);
                //    }
                //    cpp_int u(cpp_mod(pow(message.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2))));
                //    cpp_int l_u = (u - 1) / n.data.convert_to<cpp_int>();
                //    value_type decrypt_message = value_type(cpp_int(cpp_mod(l_u * mu.data.convert_to<cpp_int>(), n.data.convert_to<cpp_int>())));
                //    return decrypt_message;
                //}
            private:
                value_type lambda;
                value_type mu;
                value_type n;
            };

            template<typename FieldType, typename Generator>
            struct paillier {
                typedef typename FieldType::value_type value_type;
                const size_t bits = FieldType::modulus_bits;

                typedef paillier_public_key<FieldType, Generator> public_key_type;
                typedef paillier_private_key<FieldType, Generator> private_key_type;

                /*paillier_public_key_type public_key;
                paillier_private_key_type private_key;*/

                paillier() {
                    primes_generator<FieldType, boost::random::mt19937> generator;
                    primes = generator.generate_primes(20);
                    //n = generate_n();
                    //lambda = generate_lambda();
                    //g = generate_g();
                    //mu = generate_mu();
                    //public_key(n, g);
                    //private_key(lambda, mu, n);
                }
                paillier(value_type& first_prime, value_type& second_prime) {
                    primes = make_pair(first_prime, second_prime);
                    //n = generate_n();
                    //lambda = generate_lambda();
                    //g = generate_g();
                    //mu = generate_mu();
                    //private_key(lambda, mu, n);
                }

            private:
                pair<value_type, value_type> primes;
                value_type n;
                value_type g;
                value_type lambda;
                value_type mu;


                //value_type generate_n() {
                //    return primes.first * primes.second;
                //}

                //value_type generate_lambda() {
                //    return nil::crypto3::pubkey::lcm<FieldType>((primes.first - value_type(1)), (primes.second - value_type(1)));
                //}

                //value_type generate_g() {
                //    Generator generator(time(0));
                //    boost::random::uniform_int_distribution<cpp_int> distribution(cpp_int(1), n.pow(2).data.convert_to<cpp_int>());
                //    cpp_int value = distribution(generator);
                //    while (cpp_int(cpp_mod(pow(g.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>()), n.data.convert_to<cpp_int>())) != cpp_int(1)) {
                //        value = distribution(generator);
                //    }
                //    value_type g(value);
                //    return g;
                //}

                //value_type generate_mu() {
                //    cpp_int first_part = pow(g.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>());
                //    cpp_int second_part = pow(n.data.convert_to<cpp_int>(), cpp_int(2));
                //    cpp_int u = cpp_int(cpp_mod(first_part, second_part));
                //    cpp_int l_u = (u - 1) / n.data.convert_to<cpp_int>();
                //    value_type mu(mod_inverse(l_u, n.data.convert_to<cpp_int>()));
                //    return mu;
                //}

            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP