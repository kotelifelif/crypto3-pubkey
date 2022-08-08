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

#ifndef CRYPTO3_PUBKEY_ALGEBRAIC_OPERATIONS_HPP
#define CRYPTO3_PUBKEY_ALGEBRAIC_OPERATIONS_HPP

#include <deque>
#include <algorithm>
#include <random>
#include <iostream>
#include <typeinfo>
#include <string>
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

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template <typename FieldType>
            struct algebraic_operations {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                
                cpp_int gcd(cpp_int a, cpp_int b) {
                    while (true) {
                        if (a == cpp_int(0)) {
                            return b;
                        }
                        b = cpp_int(cpp_mod(b, a));
                        if (b == cpp_int(0)) {
                            return a;
                        }
                        a = cpp_int(cpp_mod(a, b));
                    }
                }

                cpp_int lcm(cpp_int a, cpp_int b) {
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

                cpp_int hex_to_dec(std::string& hex_value) {
                    cpp_int dec_result(0);
                    cpp_int index(1);
                    for (int i = hex_value.size() - 1; i > -1; i--) {
                        switch (hex_value[i]) {
                        case ('a'):
                            dec_result = dec_result + index * cpp_int(10);
                            break;
                        case ('b'):
                            dec_result = dec_result + index * cpp_int(11);
                            break;
                        case ('c'):
                            dec_result = dec_result + index * cpp_int(12);
                            break;
                        case ('d'):
                            dec_result = dec_result + index * cpp_int(13);
                            break;
                        case ('e'):
                            dec_result = dec_result + index * cpp_int(14);
                            break;
                        case ('f'):
                            dec_result = dec_result + index * cpp_int(15);
                            break;
                        default:
                            dec_result = dec_result + index * cpp_int(static_cast<int>(hex_value[i] - 48));
                            break;
                        }
                        index *= cpp_int(16);
                    }
                    return dec_result;
                }
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_ALGEBRAIC_OPERATIONS_HPP