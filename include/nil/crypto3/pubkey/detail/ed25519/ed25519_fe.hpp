#ifndef CRYPTO3_ED25519_FE_HPP_
#define CRYPTO3_ED25519_FE_HPP_

#include <nil/crypto3/utilities/memory_operations.hpp>

namespace nil {
    namespace crypto3 {

/**
* An element of the field \\Z/(2^255-19)
*/
        class fe25519 {
        public:
            ~fe25519() {
                secure_scrub_memory(m_fe, sizeof(m_fe));
            }

            /**
            * Zero element
            */
            fe25519(int init = 0) {
                if (init != 0 && init != 1) {
                    throw std::invalid_argument("Invalid fe25519 initial value");
                }
                memset(m_fe, 0, 10 * sizeof(int32_t));
                m_fe[0] = init;
            }

            fe25519(std::initializer_list<int32_t> x) {
                if (x.size() != 10) {
                    throw std::invalid_argument("Invalid fe25519 initializer list");
                }
                memcpy(m_fe, x.begin(), 10 * sizeof(int32_t));
            }

            fe25519(int64_t h0, int64_t h1, int64_t h2, int64_t h3, int64_t h4, int64_t h5, int64_t h6, int64_t h7,
                    int64_t h8, int64_t h9) {
                m_fe[0] = static_cast<int32_t>(h0);
                m_fe[1] = static_cast<int32_t>(h1);
                m_fe[2] = static_cast<int32_t>(h2);
                m_fe[3] = static_cast<int32_t>(h3);
                m_fe[4] = static_cast<int32_t>(h4);
                m_fe[5] = static_cast<int32_t>(h5);
                m_fe[6] = static_cast<int32_t>(h6);
                m_fe[7] = static_cast<int32_t>(h7);
                m_fe[8] = static_cast<int32_t>(h8);
                m_fe[9] = static_cast<int32_t>(h9);
            }

            fe25519(const fe25519 &other) = default;

            fe25519 &operator=(const fe25519 &other) = default;

#if !defined(CRYPTO3_BUILD_COMPILER_IS_MSVC_2013)

            fe25519(fe25519 &&other) = default;

            fe25519 &operator=(fe25519 &&other) = default;

#endif

            void from_bytes(const uint8_t b[32]);

            void to_bytes(uint8_t b[32]) const;

            bool is_zero() const {
                uint8_t s[32];
                to_bytes(s);

                uint8_t sum = 0;
                for (size_t i = 0; i != 32; ++i) {
                    sum |= s[i];
                }

                // TODO avoid ternary here
                return (sum == 0) ? 1 : 0;
            }

            /*
            return 1 if f is in {1,3,5,...,q-2}
            return 0 if f is in {0,2,4,...,q-1}
            */
            bool is_negative() const {
                // TODO could avoid most of the to_bytes computation here
                uint8_t s[32];
                to_bytes(s);
                return s[0] & 1;
            }

            static fe25519 add(const fe25519 &a, const fe25519 &b) {
                fe25519 z;
                for (size_t i = 0; i != 10; ++i) {
                    z[i] = a[i] + b[i];
                }
                return z;
            }

            static fe25519 sub(const fe25519 &a, const fe25519 &b) {
                fe25519 z;
                for (size_t i = 0; i != 10; ++i) {
                    z[i] = a[i] - b[i];
                }
                return z;
            }

            static fe25519 negate(const fe25519 &a) {
                fe25519 z;
                for (size_t i = 0; i != 10; ++i) {
                    z[i] = -a[i];
                }
                return z;
            }

            static fe25519 mul(const fe25519 &a, const fe25519 &b);

            static fe25519 sqr_iter(const fe25519 &a, size_t iter);

            static fe25519 sqr(const fe25519 &a) {
                return sqr_iter(a, 1);
            }

            static fe25519 sqr2(const fe25519 &a);

            static fe25519 pow_22523(const fe25519 &a);

            static fe25519 invert(const fe25519 &a);

            // TODO remove
            int32_t operator[](size_t i) const {
                return m_fe[i];
            }

            int32_t &operator[](size_t i) {
                return m_fe[i];
            }

        private:

            int32_t m_fe[10];
        };

        typedef fe25519 fe;

/*
fe means field element.
Here the field is
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

        inline void fe_frombytes(fe &x, const uint8_t *b) {
            x.from_bytes(b);
        }

        inline void fe_tobytes(uint8_t *b, const fe &x) {
            x.to_bytes(b);
        }

        inline void fe_copy(fe &a, const fe &b) {
            a = b;
        }

        inline int fe_isnonzero(const fe &x) {
            return x.is_zero() ? 0 : 1;
        }

        inline int fe_isnegative(const fe &x) {
            return x < 0;
        }


        inline void fe_0(fe &x) {
            x = fe25519();
        }

        inline void fe_1(fe &x) {
            x = fe25519(1);
        }

        inline void fe_add(fe &x, const fe &a, const fe &b) {
            x = fe25519::add(a, b);
        }

        inline void fe_sub(fe &x, const fe &a, const fe &b) {
            x = fe25519::sub(a, b);
        }

        inline void fe_neg(fe &x, const fe &z) {
            x = fe25519::fe25519(z);
        }

        inline void fe_mul(fe &x, const fe &a, const fe &b) {
            x = fe25519::mul(a, b);
        }

        inline void fe_sq(fe &x, const fe &z) {
            x = fe25519::fe25519(z);
        }

        inline void fe_sq_iter(fe &x, const fe &z, size_t iter) {
            x = fe25519::sqr_iter(z, iter);
        }

        inline void fe_sq2(fe &x, const fe &z) {
            x = fe25519::fe25519(z);
        }

        inline void fe_invert(fe &x, const fe &z) {
            x = fe25519::fe25519(z);
        }

        inline void fe_pow22523(fe &x, const fe &y) {
            x = fe25519::fe25519(y);
        }
    }
}

#endif
