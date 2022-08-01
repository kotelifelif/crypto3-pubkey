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
            //template <typename FieldType>
            //struct algebraic_operations {
            //    typedef FieldType::value_type value_type;
            //    
            //    value_type gcd(value_type a, value_type b) {
            //        while (true) {
            //            if (a == value_type(0)) {
            //                return b;
            //            }
            //            b = value_type(cpp_int(cpp_mod(b.data.convert_to<cpp_int>(), a.data.convert_to<cpp_int>())));
            //            if (b == value_type(0)) {
            //                return a;
            //            }
            //            a = value_type(cpp_int(cpp_mod(a.data.convert_to<cpp_int>(), b.data.convert_to<cpp_int>())));
            //        }
            //    }

            //    value_type lcm(value_type a, value_type b) {
            //        return (a / gcd(a, b)) * b;
            //    }

            //    cpp_int pow(cpp_int value, cpp_int exponent) {
            //        if (exponent <= 0)
            //            return 1;
            //        else if (exponent == 1)
            //            return value;
            //        else {
            //            if (exponent % 2 == 0) {
            //                return pow(value * value, exponent / 2);
            //            }
            //            else {
            //                return value * pow(value, exponent - 1);
            //            }
            //        }
            //    }
            //};
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_ALGEBRAIC_OPERATIONS_HPP