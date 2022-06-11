#include <iostream>
#include <exception>
#include <sstream>

#include "Analyzer.h"
#include "Match.h"

int main() {
    ffinder::File file("../CMakeLists.txt");
    suspicious::JsFileScanner scanner(file, {"target_link_libraries(${EXE_TARGET_NAME} PUBLIC ${LIB_NAME})"});
    bool status = scanner.ScanFile();

    if (status) {
        std::cout << "Found" << std::endl;
    }

    return EXIT_SUCCESS;
}