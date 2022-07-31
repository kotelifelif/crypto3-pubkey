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

#ifndef CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP
#define CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP

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

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template <typename FieldType>
            struct paillier_public_key {
                typedef FieldType::value_type value_type;

                value_type encrypt(value_type message) {
                    value_type n = generate_n();
                    mt19937 generator(time(0));
                    boost::random::uniform_int_distribution<cpp_int> distribution(1, n.data.convert_to<cpp_int>());
                    cpp_int r = distribution(generator);
                    value_type g = generate_g();
                    cpp_int first_part = pow(g.data.convert_to<cpp_int>(), message.data.convert_to<cpp_int>()) *
                        pow(r, n.data.convert_to<cpp_int>());
                    cpp_int second_part = pow(n.data.convert_to<cpp_int>(), cpp_int(2));
                    value_type encrypt_message = value_type(cpp_int(cpp_mod(first_part, second_part)));
                    return encrypt_message;
                }
            };
            
            template <typename FieldType>
            struct paillier_private_key {
                typedef FieldType::value_type value_type;

                value_type decrypt(value_type message) {
                    value_type n = generate_n();
                    if (message > n.pow(2)) {
                        return value_type(0);
                    }
                    value_type g = generate_g();
                    value_type lambda = generate_lambda();
                    value_type mu = generate_mu();
                    cpp_int u(cpp_mod(pow(message.data.convert_to<cpp_int>(), lambda.data.convert_to<cpp_int>()), pow(n.data.convert_to<cpp_int>(), cpp_int(2))));
                    cpp_int l_u = (u - 1) / n.data.convert_to<cpp_int>();
                    value_type decrypt_message = value_type(cpp_int(cpp_mod(l_u * mu.data.convert_to<cpp_int>(), n.data.convert_to<cpp_int>())));
                    return decrypt_message;
                }
            };
            
            template <typename FieldType>
            struct paillier {
                typedef FieldType::value_type value_type;

                paillier_private_key private_key;
                paillier_public_key public_key;
            };

        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_EDDSA_HPP