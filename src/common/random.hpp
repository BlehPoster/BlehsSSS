#pragma once
#include <random>
#include <inttypes.h>
#include <limits>

namespace bleh::random {
    class random {
        template<typename T> struct range_type_check_unsigned { static inline constexpr bool valid = !std::is_same_v<std::remove_reference_t<std::remove_cv_t<T>>, uint8_t>; };
        template<typename T> struct range_type_check_signed { static inline constexpr bool valid = !std::is_same_v<std::remove_reference_t<std::remove_cv_t<T>>, int8_t>; };
        template<typename T> struct range_type_valid { static inline constexpr bool valid = std::is_integral_v<std::remove_reference_t<std::remove_cv_t<T>>>; };
    public:
        template<typename V_Type, typename R_Type = V_Type, typename = std::enable_if_t<range_type_valid<R_Type>::valid>>
        static R_Type random_number_in_range(V_Type min, V_Type max) {
            if constexpr (range_type_check_unsigned<V_Type>::valid && range_type_check_signed<V_Type>::valid) {
                std::uniform_int_distribution<V_Type> distr(min, max);
                return static_cast<R_Type>(distr(gen));
            }
            else if (!range_type_check_unsigned<V_Type>::valid) {
                std::uniform_int_distribution<uint16_t> distr(min, max);
                return static_cast<R_Type>(distr(gen));
            }
            else if (!range_type_check_signed<V_Type>::valid) {
                std::uniform_int_distribution<int16_t> distr(min, max);
                return static_cast<R_Type>(distr(gen));
            }
        }

        static std::vector<uint8_t> random_bytes(size_t len) {
            using v_type = decltype(random_bytes(len))::value_type;
            decltype(random_bytes(len)) r;
            for (decltype(len) i = 0; i < len; ++i) {
                r.push_back(random::random_number_in_range(std::numeric_limits<v_type>::min(), std::numeric_limits<v_type>::max()));
            }
            return r;
        }
    private:
        static std::random_device rd;
        static std::mt19937 gen;
    };
}