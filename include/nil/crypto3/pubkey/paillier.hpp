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

#include <vector>
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

            template<typename FieldType, typename Hash>
            struct paillier_public_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                typedef std::vector<value_type> internal_accumulator_type;
                typedef std::vector<cpp_int> cipher_text;
                const size_t bits = FieldType::modulus_bits;

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

                paillier_public_key(const paillier_public_key<FieldType, Hash>& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                }
                
                paillier_public_key& operator=(const paillier_public_key<FieldType, Hash>& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                    return *this;
                }

                paillier_public_key(paillier_public_key<FieldType, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                }

                paillier_public_key& operator=(paillier_public_key<FieldType, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_set(this->n, key.n);
                    mpz_set(this->g, key.g);
                    return *this;
                }

                cipher_text encrypt(internal_accumulator_type& message) {                    
                    cipher_text encrypted_text;
                    for (auto& letter : message) {
                        mpz_t mpz_letter;
                        mpz_init_set_str(mpz_letter, letter.data.template convert_to<cpp_int>().str().c_str(), 10);
                        if (mpz_cmp(mpz_letter, this->n) > 0) {
                            mpz_clear(mpz_letter);
                            return cipher_text{};
                        }

                        mpz_t n_pow_2;
                        mpz_init(n_pow_2);
                        mpz_mul(n_pow_2, n, n);
                        mpz_t r;
                        mpz_init(r);
                        gmp_randstate_t rstate;
                        gmp_randinit_mt(rstate);
                        gmp_randseed_ui(rstate, time(0));
                        mpz_urandomm(r, rstate, n);
                        mpz_add_ui(r, r, 1);

                        mpz_t encrypt;
                        mpz_t first_part;
                        mpz_t second_part;
                        mpz_init(encrypt);
                        mpz_init(first_part);
                        mpz_init(second_part);
                        mpz_powm(first_part, g, mpz_letter, n_pow_2);
                        mpz_powm(second_part, r, n, n_pow_2);
                        mpz_mul(encrypt, first_part, second_part);
                        mpz_mod(encrypt, encrypt, n_pow_2);

                        mpz_int encrypt_letter = encrypt;
                        encrypted_text.push_back(encrypt_letter.convert_to<cpp_int>());

                        gmp_randclear(rstate);
                        mpz_clear(first_part);
                        mpz_clear(second_part);
                        mpz_clear(encrypt);
                        mpz_clear(n_pow_2);
                        mpz_clear(mpz_letter);
                    }
                    return encrypted_text;
                  }

                bool verify(cpp_int& s1, cpp_int& s2, internal_accumulator_type& message) {
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    mpz_t n_pow_2;
                    mpz_init(n_pow_2);
                    mpz_mul(n_pow_2, n, n);
                    mpz_t first_part;
                    mpz_init(first_part);
                    mpz_t mpz_s1;
                    mpz_init(mpz_s1);
                    mpz_set_str(mpz_s1, s1.str().c_str(), 10);
                    mpz_powm(first_part, g, mpz_s1, n_pow_2);
                    mpz_t mpz_s2;
                    mpz_init(mpz_s2);
                    mpz_set_str(mpz_s2, s2.str().c_str(), 10);
                    mpz_t second_part;
                    mpz_init(second_part);
                    mpz_set_str(mpz_s2, s2.str().c_str(), 10);
                    mpz_powm(second_part, mpz_s2, n, n_pow_2);
                    mpz_t mpz_value;
                    mpz_init(mpz_value);
                    mpz_mul(mpz_value, first_part, second_part);
                    mpz_mod(mpz_value, mpz_value, n_pow_2);                

                    mpz_int mpz_int_value = mpz_value;
                    cpp_int value = mpz_int_value.convert_to<cpp_int>();
                    
                    std::string string_message;
                    for (auto& letter : message) {
                        string_message.insert(string_message.size(), letter.data.template convert_to<cpp_int>().str());
                        string_message.push_back(' ');
                    }
                    string_message.pop_back();
                    digest_type hashed_message = nil::crypto3::hash<Hash>(string_message);
                    string string_hashed_message = to_string(hashed_message);
                    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);

                    bool result;
                    if (hash_function_result == value)
                        result = true;
                    else
                        result = false;

                    mpz_clear(n_pow_2);
                    mpz_clear(first_part);
                    mpz_clear(second_part);
                    mpz_clear(mpz_s2);
                    mpz_clear(mpz_s1);
                    mpz_clear(mpz_value);
                    
                    return result;
                }
            private:
                mpz_t n;
                mpz_t g;
            };

            template<typename FieldType, typename Hash>
            struct paillier_private_key {
                typedef typename FieldType::value_type value_type;
                typedef typename value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                typedef std::vector<cpp_int> internal_accumulator_type;
                typedef std::vector<cpp_int> decipher_text;
                typedef pair<cpp_int, cpp_int> signature_type;
                const size_t bits = FieldType::modulus_bits;


                paillier_private_key() {
                    mpz_init(n);
                    mpz_init(g);
                    mpz_init(lambda);
                    mpz_init(mu);
                }

                paillier_private_key(const paillier_private_key<FieldType, Hash>& key) {
                    mpz_init(n);
                    mpz_init(g);
                    mpz_init(lambda);
                    mpz_init(mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                }

                paillier_private_key& operator=(const paillier_private_key<FieldType, Hash>& key) {
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

                paillier_private_key(paillier_private_key<FieldType, Hash>&& key) {
                    mpz_init(this->n);
                    mpz_init(this->g);
                    mpz_init(this->lambda);
                    mpz_init(this->mu);
                    mpz_set(lambda, key.lambda);
                    mpz_set(mu, key.mu);
                    mpz_set(n, key.n);
                    mpz_set(g, key.g);
                }

                paillier_private_key& operator=(paillier_private_key<FieldType, Hash>&& key) {
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

                decipher_text decrypt(internal_accumulator_type& message) {
                    decipher_text decrypted_text;
                    for (auto& letter : message) {
                        mpz_t n_pow_2;
                        mpz_init(n_pow_2);
                        mpz_mul(n_pow_2, n, n);
                        mpz_t mpz_letter;
                        mpz_init_set_str(mpz_letter, letter.str().c_str(), 10);

                        if (mpz_cmp(mpz_letter, n_pow_2) > 0) {
                            mpz_clear(mpz_letter);
                            mpz_clear(n_pow_2);
                            return decipher_text{cpp_int(0)};
                        }

                        mpz_powm(mpz_letter, mpz_letter, lambda, n_pow_2);
                        mpz_sub_ui(mpz_letter, mpz_letter, 1);
                        mpz_div(mpz_letter, mpz_letter, n);
                        mpz_mul(mpz_letter, mpz_letter, mu);
                        mpz_mod(mpz_letter, mpz_letter, n);


                        mpz_int decrypted_letter = mpz_letter;
                        decrypted_text.push_back(decrypted_letter.convert_to<cpp_int>());

                        mpz_clear(mpz_letter);
                        mpz_clear(n_pow_2);
                    }
                    return decrypted_text;
                }

                signature_type sign(internal_accumulator_type& message) {
                    std::string string_message;
                    for (auto& letter : message) {
                        string_message.insert(string_message.size(), letter.str());
                        string_message.push_back(' ');
                    }
                    string_message.pop_back();
                    digest_type hashed_message = nil::crypto3::hash<Hash>(string_message);
                    nil::crypto3::pubkey::algebraic_operations<FieldType> op;
                    string string_hashed_message = to_string(hashed_message);
                    cpp_int hash_function_result = op.hex_to_dec(string_hashed_message);
                    mpz_t hash_result;
                    mpz_init(hash_result);
                    mpz_set_str(hash_result, hash_function_result.str().c_str(), 10);

                    mpz_t n_pow_2;
                    mpz_init(n_pow_2);
                    mpz_mul(n_pow_2, n, n);
                    mpz_t numerator;
                    mpz_init(numerator);
                    mpz_set(numerator, hash_result);
                    mpz_powm(numerator, numerator, lambda, n_pow_2);
                    mpz_sub_ui(numerator, numerator, 1);
                    mpz_div(numerator, numerator, n);
                    mpz_t denominator;
                    mpz_init(denominator);
                    mpz_powm(denominator, g, lambda, n_pow_2);
                    mpz_sub_ui(denominator, denominator, 1);
                    mpz_div(denominator, denominator, n);
                    mpz_invert(denominator, denominator, n);
                    mpz_mul(numerator, numerator, denominator);
                    mpz_mod(numerator, numerator, n);
                    mpz_int v = numerator;
                    cpp_int s1 = v.convert_to<cpp_int>();

                    mpz_t copy_s1;
                    mpz_init(copy_s1);
                    mpz_set_str(copy_s1, s1.str().c_str(), 10);
                    mpz_t inverse_n;
                    mpz_init(inverse_n);
                    mpz_invert(inverse_n, n, lambda);
                    mpz_t inverse_g;
                    mpz_init(inverse_g);
                    mpz_powm(inverse_g, g, copy_s1, n);
                    mpz_invert(inverse_g, inverse_g, n);
                    mpz_powm(g, g, copy_s1, n);
                    mpz_mul(inverse_g, inverse_g, hash_result);
                    mpz_powm(inverse_g, inverse_g, inverse_n, n);
                    v = inverse_g;
                    cpp_int s2 = v.convert_to<cpp_int>();

                    mpz_clear(hash_result);
                    mpz_clear(n_pow_2);
                    mpz_clear(numerator);
                    mpz_clear(denominator);
                    mpz_clear(inverse_n);
                    mpz_clear(inverse_g);
                    mpz_clear(copy_s1);


                    return make_pair(s1, s2);
                }
            private:
                mpz_t lambda;
                mpz_t mu;
                mpz_t n;
                mpz_t g;
            };

            template<typename FieldType, typename Hash>
            struct paillier {
                typedef typename FieldType::value_type value_type;
                typedef typename FieldType::value_type::data_type data_type;
                typedef typename Hash::digest_type digest_type;
                const size_t bits = FieldType::modulus_bits;

                paillier_public_key<FieldType, Hash> public_key;
                paillier_private_key<FieldType, Hash> private_key;

                ~paillier() {
                    mpz_clear(p);
                    mpz_clear(q);
                    mpz_clear(n);
                    mpz_clear(g);
                    mpz_clear(lambda);
                    mpz_clear(mu);
                }
                
                paillier() {
                    generate_primes();
                    generate_n();
                    generate_lambda();
                    generate_g();
                    generate_mu();
                    public_key = paillier_public_key<FieldType, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Hash>(lambda, mu, n, g);
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
                    public_key = paillier_public_key<FieldType, Hash>(n, g);
                    private_key = paillier_private_key<FieldType, Hash>(lambda, mu, n);
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
                    gmp_randseed_ui(rstate, time(0));
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
                    } while ((mpz_cmp_ui(gcd_result, 1) != 0) || mpz_cmp(p, mpz_t_max_value) > 0 || mpz_cmp(p, q) == 0);

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
                    gmp_randseed_ui(rstate, time(0));
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
                    
                    mpz_t mu_invert;
                    mpz_init(mu_invert);
                    while (true) {
                        mpz_powm(mu, g, lambda, n_pow_2);
                        mpz_sub_ui(mu, mu, 1);
                        mpz_div(mu, mu, n);
                        mpz_set(mu_invert, mu);
                        mpz_invert(mu_invert, mu, n);
                        mpz_mul(mu_invert, mu_invert, mu);
                        mpz_mod(mu_invert, mu_invert, n);
                        if (mpz_cmp_ui(mu_invert, 1) == 0) {
                            mpz_invert(mu, mu, n);
                            break;
                        }
                        else {
                            generate_g();
                        }
                    }

                    mpz_clear(mu_invert);
                    mpz_clear(n_pow_2);
                }

            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    CRYPTO3_PUBKEY_PAILLIER_TEMPLATE_HPP