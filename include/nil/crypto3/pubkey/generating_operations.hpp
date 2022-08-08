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

#ifndef CRYPTO3_PUBKEY_GENERATING_OPERATIONS_HPP
#define CRYPTO3_PUBKEY_GENERATING_OPERATIONS_HPP

#include <deque>
#include <algorithm>
#include <random>
#include <iostream>
#include <typeinfo>
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
using cpp_mod = nil::crypto3::multiprecision::cpp_mod;
using cpp_int = nil::crypto3::multiprecision::cpp_int;
using field = nil::crypto3::algebra::fields::alt_bn128_fq<254>;
//using value_type = nil::crypto3::algebra::fields::alt_bn128_fq<254>::value_type;
//using data_type = nil::crypto3::algebra::fields::alt_bn128_fq<254>::value_type::data_type;

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template <typename FieldType, typename Generator>
            struct primes_generator {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                const size_t bits = FieldType::modulus_bits;

                //// https://habr.com/ru/post/594135/
                //// https://progler.ru/blog/kak-generirovat-bolshie-prostye-chisla-dlya-algoritma-rsa
                cpp_int get_low_level_prime(cpp_int& min_value, cpp_int& max_value) {
                    Generator generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(min_value, max_value);
                    cpp_int value(0);
                    while (true) {
                        value = distribution(generator);
                        for (size_t prime : primes_numbers) {
                            if (cpp_int(cpp_mod(value, cpp_int(prime))) == cpp_int(0)) {
                                break;
                            }
                        }
                        return value;
                    }
                }

                cpp_int get_miller_rabin_test_prime(cpp_int min_value, cpp_int max_value, const size_t iterations_number) {
                    cpp_int low_level_prime(0);
                    while (true) {
                        low_level_prime = get_low_level_prime(min_value, max_value);
                        if (miller_rabin_test(low_level_prime, iterations_number)) {
                            return low_level_prime;
                        }
                    }
                }

                pair<cpp_int, cpp_int> generate_primes(const size_t iterations_number) {
                    pair<cpp_int, cpp_int> primes = make_pair(cpp_int(0), cpp_int(0));

                    size_t value_bits_size(bits);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int min_value = op.pow(cpp_int(2), cpp_int(value_bits_size - 1));
                    cpp_int max_value = op.pow(cpp_int(2), cpp_int(value_bits_size)) - cpp_int(1);

                    cpp_int p = get_miller_rabin_test_prime(min_value, max_value, iterations_number);
                    cpp_int q = p;

                    while (true) {
                        q = get_miller_rabin_test_prime(min_value, max_value, iterations_number);
                        if ((op.gcd(p * q, (p - 1) * (q - 1)) == cpp_int(1)) && (p != q)) {
                            break;
                        }
                    }

                    primes = make_pair(p, q);
                    return primes;
                }
            private:
                deque<size_t> primes_numbers{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                              31, 37, 41, 43, 47, 53, 59, 61, 67,
                              71, 73, 79, 83, 89, 97, 101, 103,
                              107, 109, 113, 127, 131, 137, 139,
                              149, 151, 157, 163, 167, 173, 179,
                              181, 191, 193, 197, 199, 211, 223,
                              227, 229, 233, 239, 241, 251, 257,
                              263, 269, 271, 277, 281, 283, 293,
                              307, 311, 313, 317, 331, 337, 347, 349 };
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_GENERATING_OPERATIONS_HPP