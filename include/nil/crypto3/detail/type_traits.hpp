//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_TYPE_TRAITS_HPP
#define CRYPTO3_TYPE_TRAITS_HPP

#include <complex>

#define GENERATE_HAS_MEMBER_TYPE(Type)                                                \
                                                                                      \
    template<class T>                                                                 \
    class HasMemberType_##Type {                                                      \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            struct Type { };                                                          \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(typename U::Type *);                                          \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##Type : public std::integral_constant<bool, HasMemberType_##Type<T>::RESULT> { };

#define GENERATE_HAS_MEMBER(member)                                                   \
                                                                                      \
    template<class T>                                                                 \
    class HasMember_##member {                                                        \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            int member;                                                               \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(decltype(U::member) *);                                       \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##member : public std::integral_constant<bool, HasMember_##member<T>::RESULT> { };

#define GENERATE_HAS_MEMBER_FUNCTION(Function, ...)                                  \
                                                                                     \
    template<typename T>                                                             \
    struct has_##Function {                                                          \
        struct Fallback {                                                            \
            void Function(##__VA_ARGS__);                                            \
        };                                                                           \
                                                                                     \
        struct Derived : Fallback { };                                               \
                                                                                     \
        template<typename C, C>                                                      \
        struct ChT;                                                                  \
                                                                                     \
        template<typename C>                                                         \
        static char (&f(ChT<void (Fallback::*)(##__VA_ARGS__), &C::Function> *))[1]; \
                                                                                     \
        template<typename C>                                                         \
        static char (&f(...))[2];                                                    \
                                                                                     \
        static bool const value = sizeof(f<Derived>(0)) == 2;                        \
    };

#define GENERATE_HAS_MEMBER_CONST_FUNCTION(Function, ...)                                  \
                                                                                           \
    template<typename T>                                                                   \
    struct has_##Function {                                                                \
        struct Fallback {                                                                  \
            void Function(##__VA_ARGS__) const;                                            \
        };                                                                                 \
                                                                                           \
        struct Derived : Fallback { };                                                     \
                                                                                           \
        template<typename C, C>                                                            \
        struct ChT;                                                                        \
                                                                                           \
        template<typename C>                                                               \
        static char (&f(ChT<void (Fallback::*)(##__VA_ARGS__) const, &C::Function> *))[1]; \
                                                                                           \
        template<typename C>                                                               \
        static char (&f(...))[2];                                                          \
                                                                                           \
        static bool const value = sizeof(f<Derived>(0)) == 2;                              \
    };

#define GENERATE_HAS_MEMBER_RETURN_FUNCTION(Function, ReturnType, ...)                       \
                                                                                             \
    template<typename T>                                                                     \
    struct has_##Function {                                                                  \
        struct Dummy {                                                                       \
            typedef void ReturnType;                                                         \
        };                                                                                   \
        typedef typename std::conditional<has_##ReturnType<T>::value, T, Dummy>::type TType; \
        typedef typename TType::ReturnType type;                                             \
                                                                                             \
        struct Fallback {                                                                    \
            type Function(##__VA_ARGS__);                                                    \
        };                                                                                   \
                                                                                             \
        struct Derived : TType, Fallback { };                                                \
                                                                                             \
        template<typename C, C>                                                              \
        struct ChT;                                                                          \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(ChT<type (Fallback::*)(##__VA_ARGS__), &C::Function> *))[1];         \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(...))[2];                                                            \
                                                                                             \
        static bool const value = sizeof(f<Derived>(0)) == 2;                                \
    };

#define GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(Function, ReturnType, ...)                 \
                                                                                             \
    template<typename T>                                                                     \
    struct has_##Function {                                                                  \
        struct Dummy {                                                                       \
            typedef void ReturnType;                                                         \
        };                                                                                   \
        typedef typename std::conditional<has_##ReturnType<T>::value, T, Dummy>::type TType; \
        typedef typename TType::ReturnType type;                                             \
                                                                                             \
        struct Fallback {                                                                    \
            type Function(##__VA_ARGS__) const;                                              \
        };                                                                                   \
                                                                                             \
        struct Derived : TType, Fallback { };                                                \
                                                                                             \
        template<typename C, C>                                                              \
        struct ChT;                                                                          \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(ChT<type (Fallback::*)(##__VA_ARGS__) const, &C::Function> *))[1];   \
                                                                                             \
        template<typename C>                                                                 \
        static char (&f(...))[2];                                                            \
                                                                                             \
        static bool const value = sizeof(f<Derived>(0)) == 2;                                \
    };

namespace nil {
    namespace crypto3 {
        namespace detail {
            GENERATE_HAS_MEMBER_TYPE(iterator)
            GENERATE_HAS_MEMBER_TYPE(const_iterator)

            GENERATE_HAS_MEMBER_TYPE(encoded_value_type)
            GENERATE_HAS_MEMBER_TYPE(encoded_block_type)
            GENERATE_HAS_MEMBER_TYPE(decoded_value_type)
            GENERATE_HAS_MEMBER_TYPE(decoded_block_type)

            GENERATE_HAS_MEMBER_TYPE(block_type)
            GENERATE_HAS_MEMBER_TYPE(digest_type)
            GENERATE_HAS_MEMBER_TYPE(key_type)
            GENERATE_HAS_MEMBER_TYPE(key_schedule_type)
            GENERATE_HAS_MEMBER_TYPE(word_type)

            GENERATE_HAS_MEMBER(encoded_value_bits)
            GENERATE_HAS_MEMBER(encoded_block_bits)
            GENERATE_HAS_MEMBER(decoded_value_bits)
            GENERATE_HAS_MEMBER(decoded_block_bits)

            GENERATE_HAS_MEMBER(block_bits)
            GENERATE_HAS_MEMBER(digest_bits)
            GENERATE_HAS_MEMBER(key_bits)
            GENERATE_HAS_MEMBER(min_key_bits)
            GENERATE_HAS_MEMBER(max_key_bits)
            GENERATE_HAS_MEMBER(key_schedule_bits)
            GENERATE_HAS_MEMBER(word_bits)

            GENERATE_HAS_MEMBER(rounds)

            GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(begin, const_iterator)
            GENERATE_HAS_MEMBER_CONST_RETURN_FUNCTION(end, const_iterator)

            GENERATE_HAS_MEMBER_RETURN_FUNCTION(encode, block_type)
            GENERATE_HAS_MEMBER_RETURN_FUNCTION(decode, block_type)

            GENERATE_HAS_MEMBER_RETURN_FUNCTION(encrypt, block_type)
            GENERATE_HAS_MEMBER_RETURN_FUNCTION(decrypt, block_type)

            GENERATE_HAS_MEMBER_FUNCTION(generate)
            GENERATE_HAS_MEMBER_CONST_FUNCTION(check)

            GENERATE_HAS_MEMBER_TYPE(underlying_field_type)
            GENERATE_HAS_MEMBER_TYPE(value_type)
            GENERATE_HAS_MEMBER_TYPE(modulus_type)
            GENERATE_HAS_MEMBER_TYPE(base_field_type)
            GENERATE_HAS_MEMBER_TYPE(number_type)
            GENERATE_HAS_MEMBER_TYPE(scalar_field_type)
            GENERATE_HAS_MEMBER_TYPE(g1_type)
            GENERATE_HAS_MEMBER_TYPE(g2_type)
            GENERATE_HAS_MEMBER_TYPE(gt_type)

            GENERATE_HAS_MEMBER(value_bits)
            GENERATE_HAS_MEMBER(modulus_bits)
            GENERATE_HAS_MEMBER(base_field_bits)
            GENERATE_HAS_MEMBER(base_field_modulus)
            GENERATE_HAS_MEMBER(scalar_field_bits)
            GENERATE_HAS_MEMBER(scalar_field_modulus)
            GENERATE_HAS_MEMBER(arity)
            GENERATE_HAS_MEMBER(p)
            GENERATE_HAS_MEMBER(q)

            template<typename T>
            struct is_iterator {
                static char test(...);

                template<typename U, typename = typename std::iterator_traits<U>::difference_type,
                         typename = typename std::iterator_traits<U>::pointer,
                         typename = typename std::iterator_traits<U>::reference,
                         typename = typename std::iterator_traits<U>::value_type,
                         typename = typename std::iterator_traits<U>::iterator_category>
                static long test(U &&);

                constexpr static bool value = std::is_same<decltype(test(std::declval<T>())), long>::value;
            };

            template<typename Range>
            struct is_range {
                static const bool value = has_begin<Range>::value && has_end<Range>::value;
            };

            template<typename Container>
            struct is_container {
                static const bool value =
                    has_const_iterator<Container>::value && has_begin<Container>::value && has_end<Container>::value;
            };

            template<typename T>
            struct is_codec {
                static const bool value = has_encoded_value_type<T>::value && has_encoded_value_bits<T>::value &&
                                          has_decoded_value_type<T>::value && has_decoded_value_bits<T>::value &&
                                          has_encoded_block_type<T>::value && has_encoded_block_bits<T>::value &&
                                          has_decoded_block_type<T>::value && has_decoded_block_bits<T>::value &&
                                          has_encode<T>::value && has_decode<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_block_cipher {
                static const bool value = has_word_type<T>::value && has_word_bits<T>::value &&
                                          has_block_type<T>::value && has_block_bits<T>::value &&
                                          has_key_type<T>::value && has_key_bits<T>::value && has_rounds<T>::value &&
                                          has_encrypt<T>::value && has_decrypt<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_hash {
            private:
                typedef char one;
                typedef struct {
                    char array[2];
                } two;

                template<typename C>
                static one test_construction_type(typename C::construction::type *);

                template<typename C>
                static two test_construction_type(...);

                template<typename C>
                static one test_construction_params(typename C::construction::params_type *);

                template<typename C>
                static two test_construction_params(...);

            public:
                static const bool value = has_digest_type<T>::value && has_digest_bits<T>::value &&
                                          sizeof(test_construction_type<T>(0)) == sizeof(one) &&
                                          sizeof(test_construction_params<T>(0)) == sizeof(one);
                typedef T type;
            };

            template<typename T>
            struct is_mac {
                static const bool value = has_digest_type<T>::value && has_digest_bits<T>::value &&
                                          has_block_type<T>::value && has_block_bits<T>::value &&
                                          has_key_type<T>::value && has_key_bits<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_kdf {
                static const bool value = has_digest_type<T>::value && has_digest_bits<T>::value &&
                                          has_key_type<T>::value && has_max_key_bits<T>::value &&
                                          has_min_key_bits<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_passhash {
                static const bool value = has_generate<T>::value && has_check<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_curve {
                static const bool value = has_base_field_bits<T>::value && has_base_field_type<T>::value &&
                                          has_number_type<T>::value && has_base_field_modulus<T>::value &&
                                          has_scalar_field_bits<T>::value && has_scalar_field_type<T>::value &&
                                          has_scalar_field_modulus<T>::value && has_g1_type<T>::value &&
                                          has_g2_type<T>::value && has_gt_type<T>::value && has_p<T>::value &&
                                          has_q<T>::value;
                typedef T type;
            };

            template<typename T> //TODO: we should add some other params to curve group policy to identify it more clearly
            struct is_curve_group {
                static const bool value = has_value_type<T>::value && has_underlying_field_type<T>::value &&
                                          has_value_bits<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_field {
                static const bool value = has_value_type<T>::value && has_value_bits<T>::value &&
                                          has_modulus_type<T>::value && has_modulus_bits<T>::value &&
                                          has_number_type<T>::value && has_arity<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_fp_field {
                static const bool value = has_value_type<T>::value && has_value_bits<T>::value &&
                                          has_modulus_type<T>::value && has_modulus_bits<T>::value &&
                                          has_number_type<T>::value && has_arity<T>::value &&
                                          T::arity == 1;
                typedef T type;
            };

            template<typename T>
            struct is_complex : std::false_type { };
            template<typename T>
            struct is_complex<std::complex<T>> : std::true_type { };
            template<typename T>
            constexpr bool is_complex_v = is_complex<T>::value;

            template<typename T>
            struct remove_complex {
                using type = T;
            };
            template<typename T>
            struct remove_complex<std::complex<T>> {
                using type = T;
            };
            template<typename T>
            using remove_complex_t = typename remove_complex<T>::type;

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TYPE_TRAITS_HPP
