#include <ares.h>
#include <iostream>

int main(int argc, char **argv) {
    // Initialize the c-ares library
    ares_library_init(ARES_LIB_INIT_ALL);

    // A simple input fuzzing loop using AFL
    while (__AFL_LOOP(10000)) {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <fuzzed_input_file>" << std::endl;
            return 1;
        }

        // Read input from AFL fuzzing test case
        FILE *f = fopen(argv[1], "rb");
        if (!f) {
            std::cerr << "Failed to open input file." << std::endl;
            return 1;
        }

        fseek(f, 0, SEEK_END);
        size_t length = ftell(f);
        fseek(f, 0, SEEK_SET);

        unsigned char *buffer = new unsigned char[length];
        fread(buffer, 1, length, f);
        fclose(f);

        // Fuzz the DNS parsing function in c-ares
        struct ares_addrinfo *result;
        ares_parse_a_reply(buffer, length, nullptr, &result);

        // Cleanup
        ares_freeaddrinfo(result);
        delete[] buffer;
    }

    ares_library_cleanup();
    return 0;
}
