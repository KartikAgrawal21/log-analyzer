// Runs every registered TEST. Optional argument: substring filter on "Suite.Name".
#include <exception>
#include <iostream>
#include <string>

#include "testkit.hpp"

int main(int argc, char** argv) {
    const std::string filter = argc > 1 ? argv[1] : "";
    int passed = 0;
    int failed = 0;

    for (const auto& test : testkit::registry()) {
        if (!filter.empty() && test.name.find(filter) == std::string::npos) continue;
        try {
            test.fn();
            ++passed;
            std::cout << "[  OK  ] " << test.name << "\n";
        } catch (const testkit::Failure& f) {
            ++failed;
            std::cout << "[ FAIL ] " << test.name << "\n         " << f.message << "\n";
        } catch (const std::exception& e) {
            ++failed;
            std::cout << "[ FAIL ] " << test.name << "\n         unexpected exception: " << e.what() << "\n";
        } catch (...) {
            ++failed;
            std::cout << "[ FAIL ] " << test.name << "\n         unexpected non-std exception\n";
        }
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
