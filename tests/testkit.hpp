#pragma once
// Tiny dependency-free test framework.
//
//   TEST(Suite, Name) { CHECK(x > 0); CHECK_EQ(a, b); CHECK_THROWS(f(), std::out_of_range); }
//
// Tests self-register at static-init time; tests/test_main.cpp runs them all.
// A failed CHECK aborts only the current test.

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace testkit {

struct Failure {
    std::string message;
};

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

template <class T, class = void>
struct is_streamable : std::false_type {};
template <class T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <class T>
std::string show(const T& value) {
    if constexpr (is_streamable<T>::value) {
        std::ostringstream os;
        os << value;
        return os.str();
    } else {
        return "<unprintable>";
    }
}

inline std::string where(const char* file, int line) {
    return std::string(file) + ":" + std::to_string(line) + ": ";
}

}  // namespace testkit

#define TEST(suite, name)                                                               \
    static void suite##_##name();                                                       \
    static ::testkit::Registrar suite##_##name##_registrar(#suite "." #name, suite##_##name); \
    static void suite##_##name()

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond))                                                                    \
            throw ::testkit::Failure{::testkit::where(__FILE__, __LINE__) +             \
                                     "CHECK(" #cond ") failed"};                        \
    } while (0)

// The operands are COPIED, not bound by reference: with `auto&& x = f().member;` MSVC does
// not keep the temporary returned by f() alive, so CHECK_EQ(run(...).code, 2) read freed
// memory (AddressSanitizer: stack-use-after-scope), with or without parentheses. Tests
// compare cheap values, so a copy is fine; operands must therefore be copyable.
#define CHECK_EQ(a, b)                                                                  \
    do {                                                                                \
        const auto _tk_a = (a);                                                         \
        const auto _tk_b = (b);                                                         \
        if (!(_tk_a == _tk_b))                                                          \
            throw ::testkit::Failure{::testkit::where(__FILE__, __LINE__) +             \
                                     "CHECK_EQ(" #a ", " #b ") failed: " +              \
                                     ::testkit::show(_tk_a) + " vs " +                  \
                                     ::testkit::show(_tk_b)};                           \
    } while (0)

#define CHECK_THROWS(expr, ExType)                                                      \
    do {                                                                                \
        bool _tk_thrown = false;                                                        \
        try {                                                                           \
            (void)(expr);                                                               \
        } catch (const ExType&) {                                                       \
            _tk_thrown = true;                                                          \
        }                                                                               \
        if (!_tk_thrown)                                                                \
            throw ::testkit::Failure{::testkit::where(__FILE__, __LINE__) +             \
                                     "CHECK_THROWS(" #expr ", " #ExType ") did not throw"}; \
    } while (0)
