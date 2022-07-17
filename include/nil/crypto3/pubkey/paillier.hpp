//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_PAILLIER_HPP
#define CRYPTO3_PUBKEY_PAILLIER_HPP

#include <cmath>
#include <deque>
#include <algorithm>
#include <random>

#include <boost/math/common_factor.hpp>

using namespace std;

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            // https://habr.com/ru/post/594135/
            // https://progler.ru/blog/kak-generirovat-bolshie-prostye-chisla-dlya-algoritma-rsa
            pair<size_t, size_t> generate_primes(const size_t bits) {
                size_t value_bits_size = bits;
                size_t min_value = pow(2, (value_bits_size - 1)) + 1;
                size_t max_value = pow(2, value_bits_size) - 1;

                // Sieve of Eratosthenes
                deque<size_t> primes_numbers;
                for (size_t i = 2; i <= max_value; i++) {
                    primes_numbers.push_back(i);
                }
                for (size_t i = 2; i <= max_value; i++) {
                    for (size_t j = 2 * i; j < max_value; j += i) {
                        auto find_number = find(begin(primes_numbers), end(primes_numbers), j);
                        if (find_number != end(primes_numbers)) {
                            primes_numbers.erase(find_number);
                        }
                    }
                }
                auto less_elements_iterator = remove_if(begin(primes_numbers), end(primes_numbers),
                    [min_value](int value) {
                        return value >= min_value;
                    });
                primes_numbers.erase(begin(primes_numbers), less_elements_iterator);
                default_random_engine generator;
                uniform_int_distribution<size_t> distribution(0, primes_numbers.size() - 1);
                size_t p = primes_numbers[distribution(generator)];
                size_t index = 0;
                size_t q = primes_numbers[0];
                bool is_find = false;
                while ((p == q) || (boost::math::gcd(p * q, (p - 1) * (q - 1)) != 1)) {
                    index++;
                    q = primes_numbers[index];
                }
                return make_pair(p, q);
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_PAILLIER_HPP
