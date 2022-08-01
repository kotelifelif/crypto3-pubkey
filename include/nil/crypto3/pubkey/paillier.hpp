////---------------------------------------------------------------------------//
//// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
////
//// MIT License
////
//// Permission is hereby granted, free of charge, to any person obtaining a copy
//// of this software and associated documentation files (the "Software"), to deal
//// in the Software without restriction, including without limitation the rights
//// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//// copies of the Software, and to permit persons to whom the Software is
//// furnished to do so, subject to the following conditions:
////
//// The above copyright notice and this permission notice shall be included in all
//// copies or substantial portions of the Software.
////
//// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//// SOFTWARE.
////---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_PAILLIER_HPP
#define CRYPTO3_PUBKEY_PAILLIER_HPP

#include <deque>
#include <algorithm>
#include <random>
#include <iostream>
#include <typeinfo>

#include <boost/integer/mod_inverse.hpp>

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
using field = nil::crypto3::algebra::fields::alt_bn128_fq<254>;
using value_type = nil::crypto3::algebra::fields::alt_bn128_fq<254>::value_type;
using data_type = nil::crypto3::algebra::fields::alt_bn128_fq<254>::value_type::data_type;

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            value_type n;
            value_type g;
            value_type lambda;
            value_type mu;
            pair<value_type, value_type> primes;
            deque<size_t> primes_numbers{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
            31, 37, 41, 43, 47, 53, 59, 61, 67,
            71, 73, 79, 83, 89, 97, 101, 103,
            107, 109, 113, 127, 131, 137, 139,
            149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223,
            227, 229, 233, 239, 241, 251, 257,
            263, 269, 271, 277, 281, 283, 293,
            307, 311, 313, 317, 331, 337, 347, 349 };

            // https://habr.com/ru/post/594135/
            // https://progler.ru/blog/kak-generirovat-bolshie-prostye-chisla-dlya-algoritma-rsa
            value_type get_low_level_prime(value_type min_value, value_type max_value) {
                mt19937 generator(time(0));
                boost::random::uniform_int_distribution<cpp_int> distribution(min_value.data.convert_to<cpp_int>(), max_value.data.convert_to<cpp_int>());
                cpp_int value;
                while (true) {
                    value = distribution(generator);
                    for (size_t prime : primes_numbers) {
                        if (value_type(cpp_int(cpp_mod(value, cpp_int(prime)))) == value_type(0)) {
                            break;
                        }
                    }
                    return value_type(value);
                }
            }

            value_type get_miller_rabin_test_prime(value_type min_value, value_type max_value) {
                value_type low_level_prime;
                cpp_int cpp_int_low_level_prime;
                while (true) {
                    low_level_prime = get_low_level_prime(min_value, max_value);
                    cpp_int_low_level_prime = low_level_prime.data.convert_to<cpp_int>();
                    if (miller_rabin_test(cpp_int_low_level_prime, 20)) {
                        return low_level_prime;
                    }
                }
            }

            value_type gcd(value_type a, value_type b) {
                while (true) {
                    if (a == value_type(0)) {
                        return b;
                    }
                    b = value_type(cpp_int(cpp_mod(b.data.convert_to<cpp_int>(), a.data.convert_to<cpp_int>())));
                    if (b == value_type(0)) {
                        return a;
                    }
                    a = value_type(cpp_int(cpp_mod(a.data.convert_to<cpp_int>(), b.data.convert_to<cpp_int>())));
                }
            }

            value_type lcm(value_type a, value_type b) {
                return (a / gcd(a, b)) * b;
            }

            cpp_int pow(cpp_int value, cpp_int exponent) {
                if (exponent <= 0)
                    return 1;
                else if (exponent == 1)
                    return value;
                else {
                    if (exponent % 2 == 0) {
                        return pow(value * value, exponent / 2);
                    }
                    else {
                        return value * pow(value, exponent - 1);
                    }
                }
            }

            pair<value_type, value_type> generate_primes(const size_t bits) {
                primes = make_pair(value_type(7), value_type(11));
                size_t value_bits_size(bits);
                value_type min_value = value_type(2).pow(value_bits_size - 1);
                value_type max_value = value_type(2).pow(value_bits_size) - value_type(1);

                value_type p = get_miller_rabin_test_prime(min_value, max_value);
                value_type q = p;

                while (true) {
                    q = get_miller_rabin_test_prime(min_value, max_value);
                    if ((gcd(p * q, (p - 1) * (q - 1)) == value_type(1)) && (p != q)) {
                        break;
                    }
                }

                primes = make_pair(p, q);
                return primes;
            }
            value_type generate_n() {
                return primes.first * primes.second;
            }
            value_type generate_lambda() {
                return lcm((primes.first - value_type(1)), (primes.second - value_type(1)));
            }
            value_type generate_g() {
                boost::random::mt19937 generator(time(0));
                boost::random::uniform_int_distribution<cpp_int> distribution(cpp_int(1), n.pow(2).data.convert_to<cpp_int>());
                cpp_int value = distribution(generator);
                while (cpp_int(cpp_mod(pow(value, lambda.data.convert_to<cpp_int>()), n.data.convert_to<cpp_int>())) != cpp_int(1)) {
                    value = distribution(generator);
                }
                value_type g(value);
                return g;
            }
            value_type generate_mu() {
                cpp_int first_part = pow(g.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>());
                cpp_int second_part = pow(n.data.convert_to<cpp_int>(), cpp_int(2));
                cpp_int u = cpp_int(cpp_mod(first_part, second_part));
                cpp_int l_u = (u - 1) / n.data.convert_to<cpp_int>();
                value_type mu(mod_inverse(l_u, n.data.convert_to<cpp_int>()));
                return value_type(mu);
            }
            pair<value_type, value_type> generate_private_key() {
                return make_pair(generate_n(), generate_g());
            }
            pair<value_type, value_type> generate_public_key() {
                return make_pair(generate_lambda(), generate_mu());
            }
            void generate_variables(size_t bits) {
                primes = generate_primes(bits);
                cout << "first_prime " << primes.first.data << endl;
                cout << "second_prime " << primes.second.data << endl;
                n = generate_n();
                cout << "n " << n.data << endl;
                lambda = generate_lambda();
                cout << "lambda " << lambda.data << endl;
                g = generate_g();
                cout << "g " << g.data << endl;
                mu = generate_mu();
                cout << "mu " << mu.data << endl;
            }
            value_type encrypt(value_type message) {
                if (message > n) {
                    return value_type(0);
                }
                mt19937 generator(time(0));
                boost::random::uniform_int_distribution<cpp_int> distribution(1, n.data.convert_to<cpp_int>());
                cpp_int r = distribution(generator);
                cpp_int first_part = pow(g.data.convert_to<cpp_int>(), message.data.convert_to<cpp_int>()) *
                    pow(r, n.data.convert_to<cpp_int>());
                cpp_int second_part = pow(n.data.convert_to<cpp_int>(), cpp_int(2));
                value_type encrypt_message = value_type(cpp_int(cpp_mod(first_part, second_part)));
                return encrypt_message;
            }

            value_type decrypt(value_type message) {
                if (message > n.pow(2)) {
                    return value_type(0);
                }
                cpp_int u(cpp_mod(pow(message.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2))));
                cpp_int l_u = (u - 1) / n.data.convert_to<cpp_int>();
                value_type decrypt_message = value_type(cpp_int(cpp_mod(l_u * mu.data.convert_to<cpp_int>(), n.data.convert_to<cpp_int>())));
                return decrypt_message;
            }

            //template<typename hash>
            //pair<cpp_mod, cpp_mod> sign(hash function, hash message) {
            //    cpp_mod first_part_s1 = ((pow(funcrion(message), generate_lambda()) % pow(generate_n(), 2)) - 1) / n;
            //    
            //    /*cpp_mod second_part_s1 = ((generate_g(), generate_lambda()) % pow(generate_n(), 2)) - 1) / n;
            //    cpp_mod s1 = (first_part_s1 / second_part_s1) % generate_n();
            //    cpp_mod s2 = pow((function(message) * pow(generate_g, -s1)), ((1 / generate_n()) % generate_lambda)) % generate_n();*/
            //    return make_pair(0, 0);
            //}

            /*template<typename hash>
            bool verify(hash function, hash message) {
                pair<cpp_mod, cpp_mod> signs = sign(function, message);
                cpp_mod value = (pow(generate_g(), signs.first) * pow(signs.second, generate_n()) % (pow(generate_n(), cpp_mod(2)));
                if (function(message) == value)
                    return true;
                else
                    return false;
            }*/
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_PAILLIER_HPP