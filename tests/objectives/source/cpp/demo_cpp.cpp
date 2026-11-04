// GHIRUST objective fixture: C++ feature DLL.
//
// Covers arithmetic, branches, loops, recursion, classes with
// constructors/destructors, structs, arrays, templates, overloads, single
// inheritance, pointer and memory operations, exceptions and Rust interop.
//
// Every extern "C" export has a known result. Class methods are exported with
// their mangled names on purpose, so analysis must deal with C++ name
// mangling.
//
// Build (from a Visual Studio Developer Command Prompt or after vcvars64.bat):
//   cl /nologo /LD /O2 /EHsc /std:c++20 /Fo:..\..\build\ demo_cpp.cpp ^
//      /link /OUT:..\..\binaries\demo_cpp.dll ^
//      ..\..\binaries\demo_features.dll.lib
//
// The Rust import library demo_features.dll.lib is produced by rustc when the
// cdylib is built.

#include <cstdint>
#include <cstddef>

#define GHIRUST_EXPORT extern "C" __declspec(dllexport)

// ---------------------------------------------------------------------------
// Arithmetic and branches
// ---------------------------------------------------------------------------

GHIRUST_EXPORT std::uint64_t cpp_add(std::uint64_t a, std::uint64_t b) {
    return a + b;
}

GHIRUST_EXPORT std::uint64_t cpp_sub(std::uint64_t a, std::uint64_t b) {
    return a - b;
}

GHIRUST_EXPORT std::uint64_t cpp_mul(std::uint64_t a, std::uint64_t b) {
    return a * b;
}

GHIRUST_EXPORT std::uint64_t cpp_div(std::uint64_t a, std::uint64_t b) {
    if (b == 0) {
        return 0;
    }
    return a / b;
}

GHIRUST_EXPORT std::int32_t cpp_classify(std::int64_t value) {
    if (value < 0) {
        return 0;
    } else if (value == 0) {
        return 1;
    } else if (value < 100) {
        return 2;
    }
    return 3;
}

// ---------------------------------------------------------------------------
// Loops and recursion
// ---------------------------------------------------------------------------

GHIRUST_EXPORT std::uint64_t cpp_sum_loop(std::uint64_t n) {
    std::uint64_t total = 0;
    for (std::uint64_t index = 1; index <= n; ++index) {
        total += index;
    }
    return total;
}

GHIRUST_EXPORT std::uint64_t cpp_even_loop(std::uint64_t n) {
    std::uint64_t even_sum = 0;
    std::uint64_t index = 0;
    while (index <= n) {
        if (index % 2 == 0) {
            even_sum += index;
        }
        ++index;
    }
    return even_sum;
}

GHIRUST_EXPORT std::uint64_t cpp_fact(std::uint32_t n) {
    if (n < 2) {
        return 1;
    }
    return static_cast<std::uint64_t>(n) * cpp_fact(n - 1);
}

// ---------------------------------------------------------------------------
// Structs, arrays, pointers and memory
// ---------------------------------------------------------------------------

struct RectC {
    std::uint32_t width;
    std::uint32_t height;
};

GHIRUST_EXPORT std::uint64_t cpp_struct_area(const RectC* rect) {
    if (rect == nullptr) {
        return 0;
    }
    return static_cast<std::uint64_t>(rect->width) * rect->height;
}

GHIRUST_EXPORT std::uint64_t cpp_array_sum(const std::uint64_t* values,
                                           std::size_t length) {
    if (values == nullptr) {
        return 0;
    }
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < length; ++index) {
        total += values[index];
    }
    return total;
}

GHIRUST_EXPORT void cpp_pointer_swap(std::uint64_t* a, std::uint64_t* b) {
    if (a == nullptr || b == nullptr) {
        return;
    }
    std::uint64_t temporary = *a;
    *a = *b;
    *b = temporary;
}

GHIRUST_EXPORT void cpp_memzero(void* destination, std::size_t length) {
    if (destination == nullptr) {
        return;
    }
    std::uint8_t* bytes = static_cast<std::uint8_t*>(destination);
    for (std::size_t index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

// ---------------------------------------------------------------------------
// Classes: constructor/destructor, methods, overloads, templates, inheritance
// ---------------------------------------------------------------------------

class Counter {
public:
    Counter() : value_(0) {}
    ~Counter() = default;

    void increment(std::uint64_t step) { value_ += step; }
    std::uint64_t read() const { return value_; }

private:
    std::uint64_t value_;
};

GHIRUST_EXPORT std::uint64_t cpp_counter_run(std::uint64_t steps) {
    Counter counter;
    std::uint64_t remaining = steps;
    while (remaining > 0) {
        counter.increment(remaining & 3);
        --remaining;
    }
    return counter.read();
}

class Base {
public:
    virtual ~Base() = default;
    virtual std::uint64_t value() const { return 10; }
};

class Derived : public Base {
public:
    std::uint64_t value() const override { return 42; }
};

GHIRUST_EXPORT std::uint64_t cpp_virtual_dispatch(int use_derived) {
    Base base;
    Derived derived;
    Base* pointer = use_derived ? static_cast<Base*>(&derived)
                                : static_cast<Base*>(&base);
    return pointer->value();
}

template <typename T>
T cpp_template_scale(T value, T factor) {
    return value * factor;
}

// Exported with mangled names: overloads of cpp_scale.
__declspec(dllexport) std::int32_t cpp_scale(std::int32_t value) {
    return cpp_template_scale<std::int32_t>(value, 3);
}

__declspec(dllexport) double cpp_scale(double value) {
    return cpp_template_scale<double>(value, 3.0);
}

// extern "C" wrappers for the overloads so tests can call known entry points.
GHIRUST_EXPORT std::int32_t cpp_overload_int(std::int32_t value) {
    return cpp_scale(value);
}

GHIRUST_EXPORT double cpp_overload_double(double value) {
    return cpp_scale(value);
}

// A class method exported with its mangled name, plus a C wrapper.
class Arithmetic {
public:
    __declspec(dllexport) std::uint64_t scale(std::uint64_t value) const {
        return value * 7;
    }
};

GHIRUST_EXPORT std::uint64_t cpp_method_call(std::uint64_t value) {
    Arithmetic arithmetic;
    return arithmetic.scale(value);
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

GHIRUST_EXPORT std::int32_t cpp_exception_safe(std::int64_t divisor) {
    try {
        if (divisor == 0) {
            throw 1;
        }
        return 100 / static_cast<int>(divisor);
    } catch (...) {
        return -1;
    }
}

// ---------------------------------------------------------------------------
// Rust interop: this DLL imports features_add from demo_features.dll.
// ---------------------------------------------------------------------------

extern "C" __declspec(dllimport) std::uint64_t features_add(std::uint64_t a,
                                                            std::uint64_t b);

GHIRUST_EXPORT std::uint64_t cpp_calls_rust(std::uint64_t a, std::uint64_t b) {
    return features_add(a, b) + 1;
}
