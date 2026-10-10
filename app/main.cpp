#include <iostream>
#include <string>
#include <vector>

#include "loganalyzer/cli.hpp"

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + (argc > 0 ? 1 : 0), argv + argc);
    return loganalyzer::run_cli(args, std::cout, std::cerr);
}
