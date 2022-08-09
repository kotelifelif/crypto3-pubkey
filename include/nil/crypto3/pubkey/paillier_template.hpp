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

#include <nil/crypto3/multiprecision/gmp.hpp>

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
                const size_t bits = 5; // FieldType::modulus_bits;

                paillier_public_key() {
                    mpz_init(n);
                    mpz_init(g);
                }

                ~paillier_public_key() {
                    mpz_clear(n);
                    mpz_clear(g);
                }
        
                paillier_public_key(mpz_t& n, mpz_t& g) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, n);
                    mpz_set(this->g, g);
                }

                paillier_public_key(const paillier_public_key<FieldType, Generator, Hash>& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                }
                
                paillier_public_key& operator=(const paillier_public_key<FieldType, Generator, Hash>& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                    return *this;
                }

                paillier_public_key(paillier_public_key<FieldType, Generator, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                }

                paillier_public_key& operator=(paillier_public_key<FieldType, Generator, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                    return *this;
                }

                value_type encrypt(value_type& message) {
                    mpz_t mpz_t_message;
                    mpz_init_set_str(mpz_t_message, message.data.template convert_to<cpp_int>().str().c_str(), 10);
                    if (mpz_cmp(mpz_t_message, this->n) > 0) {
                        mpz_clear(mpz_t_message);
                        return value_type(0);
                    }
                    
                    mpz_t n;
                    mpz_init(n);
                    mpz_set_ui(n, 77);
                    mpz_t n_pow_2;
                    mpz_init(n_pow_2);
                    mpz_set_ui(n_pow_2, 5929);
                    mpz_t g;
                    mpz_init(g);
                    mpz_set_ui(g, 5652);
                    mpz_t r;
                    mpz_init(r);
                    mpz_set_ui(r, 23);
                    //mpz_init(n_pow_2);
                    //mpz_mul(n_pow_2, n, n);
                    //mpz_t r;
                    //mpz_init(r);
                    //gmp_randstate_t rstate;
                    //gmp_randinit_mt(rstate);
                    //mpz_urandomm(r, rstate, n);
                    //mpz_add_ui(r, r, 1);
                    gmp_printf("r %Zi \n", &r);

                    mpz_t encrypt;
                    mpz_t first_part;
                    mpz_t second_part;
                    mpz_init(encrypt);
                    mpz_init(first_part);
                    mpz_init(second_part);
                    mpz_powm(first_part, g, mpz_t_message, n_pow_2);
                    gmp_printf("first_part %Zi \n", &first_part);
                    mpz_powm(second_part, r, n, n_pow_2);
                    gmp_printf("second_part %Zi \n", &second_part);
                    mpz_mul(encrypt, first_part, second_part);
                    mpz_mod(encrypt, encrypt, n_pow_2);
                    gmp_printf("encrypt %Zi \n", &encrypt);

                    char* tmp = mpz_get_str(NULL, 10, mpz_t_message);
                    std::string str_encrypt = tmp;

                    void (*freefunc)(void*, size_t);
                    mp_get_memory_functions(NULL, NULL, &freefunc);
                    freefunc(tmp, strlen(tmp) + 1);

                    mpz_int v = &encrypt;
                    value_type encrypt_message = value_type(cpp_int(v.backend().data()));
                    
                    /*gmp_randclear(rstate)*/;
                    mpz_clear(first_part);
                    mpz_clear(second_part);
                    mpz_clear(encrypt);
                    mpz_clear(n_pow_2);
                    mpz_clear(mpz_t_message);

                    return encrypt_message;
                  }

                //bool verify(cpp_int& s1, cpp_int& s2, value_type& message) {
                //    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                //    cpp_int value = cpp_int(cpp_mod(op.pow(g.data.template convert_to<cpp_int>(), s1) * op.pow(s2, n.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2))));               

                //    digest_type hashed_message = nil::crypto3::hash<Hash>(message.data.template convert_to<cpp_int>().str());
                //    string string_hashed_message = to_string(hashed_message);
                //    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);

                //    if (hash_function_result == value)
                //        return true;
                //    else
                //        return false;
                //}
            private:
                mpz_t n;
                mpz_t g;
            };

            template<typename FieldType, typename Generator, typename Hash>
            struct paillier_private_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = 5; // FieldType::modulus_bits;


                paillier_private_key() {
                    mpz_init(n);
                    mpz_init(g);
                    mpz_init(lambda);
                    mpz_init(mu);
                }

                paillier_private_key(const paillier_private_key<FieldType, Generator, Hash>& key) {
                    mpz_init(n);
                    mpz_init(g);
                    mpz_init(lambda);
                    mpz_init(mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                }

                paillier_private_key& operator=(const paillier_private_key<FieldType, Generator, Hash>& key) {
                    mpz_init(n);
                    mpz_init(g);
                    mpz_init(lambda);
                    mpz_init(mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                    return *this;
                }

                ~paillier_private_key() {
                    mpz_clear(n);
                    mpz_clear(g);
                    mpz_clear(lambda);
                    mpz_clear(mu);
                }

                paillier_private_key(paillier_private_key<FieldType, Generator, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_init(this->lambda);
                    mpz_init(this->mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                }

                paillier_private_key& operator=(paillier_private_key<FieldType, Generator, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_init(this->lambda);
                    mpz_init(this->mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                    return *this;
                }
                                
                paillier_private_key(const mpz_t& lambda, const mpz_t& mu, const mpz_t& n, const mpz_t& g) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_init(this->lambda);
                    mpz_init(this->mu);
                    mpz_set(this->lambda, lambda);
                    mpz_set(this->mu, mu);
                    mpz_set(this->n, n);
                    mpz_set(this->g, g);
                }

                value_type decrypt(value_type& message) {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    mpz_t n_pow_2;
                    mpz_init(n_pow_2);
                    mpz_mul(n_pow_2, n, n);
                    mpz_t mpz_t_message;
                    mpz_init_set_str(mpz_t_message, message.data.template convert_to<cpp_int>().str().c_str(), 10);
                    if (mpz_cmp(mpz_t_message, n_pow_2) > 0) {
                        mpz_clear(mpz_t_message);
                        mpz_clear(n_pow_2);
                        return value_type(0);
                    }

                    mpz_powm(mpz_t_message, mpz_t_message, lambda, n_pow_2);
                    mpz_sub_ui(mpz_t_message, mpz_t_message, 1);
                    mpz_div(mpz_t_message, mpz_t_message, n);
                    mpz_mul(mpz_t_message, mpz_t_message, mu);
                    mpz_mod(mpz_t_message, mpz_t_message, n);

                    char* tmp = mpz_get_str(NULL, 10, mpz_t_message);
                    std::string str_decrypt = tmp;

                    void (*freefunc)(void*, size_t);
                    mp_get_memory_functions(NULL, NULL, &freefunc);
                    freefunc(tmp, strlen(tmp) + 1);
                    
                    value_type decrypt_message = value_type(cpp_int(str_decrypt));
                    mpz_clear(mpz_t_message);
                    mpz_clear(n_pow_2);
                    return decrypt_message;
                }

                //pair<cpp_int, cpp_int> sign(value_type& message) {
                //    digest_type hashed_message = nil::crypto3::hash<Hash>(message.data.template convert_to<cpp_int>().str());
                //    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                //    string string_hashed_message = to_string(hashed_message);
                //    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);

                //    cpp_int numerator = (cpp_int(cpp_mod(op.pow(hash_function_result, lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.template convert_to<cpp_int>();
                //    cpp_int denominator = (cpp_int(cpp_mod(op.pow(g.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>()), op.pow(n.data.template convert_to<cpp_int>(), cpp_int(2)))) - cpp_int(1)) / n.data.template convert_to<cpp_int>();
                //    cpp_int s1 = cpp_int(cpp_mod(mod_inverse(denominator, n.data.template convert_to<cpp_int>()) * numerator, n.data.template convert_to<cpp_int>()));

                //    cpp_int inverse_n = mod_inverse(n.data.template convert_to<cpp_int>(), lambda.data.template convert_to<cpp_int>());
                //    cpp_int inverse_g = mod_inverse(op.pow(g.data.template convert_to<cpp_int>(), s1), n.data.template convert_to<cpp_int>());
                //    cpp_int s2 = cpp_int(cpp_mod(op.pow(hash_function_result * inverse_g, inverse_n), n.data.template convert_to<cpp_int>()));

                //    return make_pair(s1, s2);
                //}
            private:
                mpz_t lambda;
                mpz_t mu;
                mpz_t n;
                mpz_t g;
            };

            template<typename FieldType, typename Generator, typename Hash>
            struct paillier {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = 5;// FieldType::modulus_bits;

                paillier_public_key<FieldType, Generator, Hash> public_key;
                paillier_private_key<FieldType, Generator, Hash> private_key;

                ~paillier() {
                    mpz_clear(p);
                    mpz_clear(q);
                    mpz_clear(n);
                    mpz_clear(g);
                    mpz_clear(lambda);
                    mpz_clear(mu);
                }
                
                paillier(const int iterations_number = 20) {
                    generate_primes();
                    gmp_printf("p %Zi \n", &p);
                    gmp_printf("q %Zi \n", &q);
                    generate_n();
                    gmp_printf("n %Zi \n", &n);
                    generate_lambda();
                    gmp_printf("lambda %Zi \n", &lambda);
                    generate_g();
                    gmp_printf("g %Zi \n", &g);
                    generate_mu();
                    gmp_printf("mu %Zi \n", &mu);
                    public_key = paillier_public_key<FieldType, Generator, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Generator, Hash>(lambda, mu, n, g);
                }
                paillier(value_type& first_prime, value_type& second_prime) {
                    mpz_init(p);
                    mpz_init(q);
                    mpz_init_set_str(p, first_prime.data.template convert_to<cpp_int>().str().c_str(), 10);
                    mpz_init_set_str(q, second_prime.data.template convert_to<cpp_int>().str().c_str(), 10);
                    generate_n();
                    generate_lambda();
                    generate_g();
                    generate_mu();
                    public_key = paillier_public_key<FieldType, Generator, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Generator, Hash>(lambda, mu, n);
                }

            private:
                mpz_t p;
                mpz_t q;
                mpz_t n;
                mpz_t g;
                mpz_t lambda;
                mpz_t mu;


                void generate_primes() {
                    size_t value_bits_size(bits);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    cpp_int max_value = op.pow(cpp_int(2), cpp_int(value_bits_size)) - cpp_int(1);

                    mpz_init(p);
                    mpz_init(q);
                    mpz_t mpz_t_max_value;
                    mpz_init(mpz_t_max_value);
                    gmp_randstate_t rstate;
                    gmp_randinit_mt(rstate);
                    mpz_init_set_str(mpz_t_max_value, max_value.str().c_str(), 10);
                    do {
                        mpz_rrandomb(p, rstate, bits);
                        mpz_nextprime(p, p);
                    } while (mpz_cmp(p, mpz_t_max_value) > 0);

                    mpz_t p_minus_1, q_minus_1, gcd_first_part, gcd_second_part, gcd_result;
                    mpz_init(p_minus_1);
                    mpz_init(q_minus_1);
                    mpz_init(gcd_first_part);
                    mpz_init(gcd_second_part);
                    mpz_init(gcd_result);
                    do {
                        mpz_rrandomb(q, rstate, bits);
                        mpz_nextprime(q, q);
                        mpz_sub_ui(p_minus_1, p, 1);
                        mpz_sub_ui(q_minus_1, q, 1);
                        mpz_mul(gcd_first_part, p_minus_1, q_minus_1);
                        mpz_mul(gcd_second_part, p, q);
                        mpz_gcd(gcd_result, gcd_first_part, gcd_second_part);
                    } while ((mpz_cmp_ui(gcd_result, 1) != 0) || mpz_cmp(p, mpz_t_max_value) > 0);

                    mpz_clear(mpz_t_max_value);
                    mpz_clear(p_minus_1);
                    mpz_clear(q_minus_1);
                    mpz_clear(gcd_first_part);
                    mpz_clear(gcd_second_part);
                    mpz_clear(gcd_result);
                    gmp_randclear(rstate);
                }

                void generate_n() {
                    mpz_init(n);
                    mpz_mul(n, p, q);
                }

                void generate_lambda() {
                    mpz_init(lambda);
                    mpz_t p_minus_1;
                    mpz_t q_minus_1;
                    mpz_init(p_minus_1);
                    mpz_init(q_minus_1);
                    mpz_sub_ui(q_minus_1, q, 1);
                    mpz_sub_ui(p_minus_1, p, 1);
                    mpz_lcm(lambda, p_minus_1, q_minus_1);
                    mpz_clear(p_minus_1);
                    mpz_clear(q_minus_1);
                }

                void generate_g() {
                    mpz_init(g);
                    gmp_randstate_t rstate;
                    gmp_randinit_mt(rstate);
                    mpz_t n_pow_2;
                    mpz_init(n_pow_2);
                    mpz_mul(n_pow_2, n, n);

                    mpz_t copy_g;
                    mpz_init(copy_g);
                    do {
                        mpz_urandomm(g, rstate, n_pow_2);
                        mpz_add_ui(g, g, 1);
                        mpz_set(copy_g, g);
                        mpz_powm(copy_g, copy_g, lambda, n);
                    } while (mpz_cmp_ui(copy_g, 1) != 0);

                    mpz_clear(copy_g);
                    gmp_randclear(rstate);
                }

                void generate_mu() {
                    mpz_init(mu);
                    mpz_t u;
                    mpz_t n_pow_2;
                    mpz_init(u);
                    mpz_init(n_pow_2);
                    mpz_mul(n_pow_2, n, n);
                    mpz_powm(mu, g, lambda, n_pow_2);
                    mpz_sub_ui(mu, mu, 1);
                    mpz_div(mu, mu, n);
                    mpz_invert(mu, mu, n);
                    mpz_clear(n_pow_2);
                }

            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP