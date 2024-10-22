#include "ares.h"
#include <arpa/inet.h>  // For sockaddr and related structures
#include <iostream>
#include <cstring>

int main(int argc, char **argv) {
    // Initialize the c-ares library
    ares_library_init(ARES_LIB_INIT_ALL);

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    // Read input from file (for AFL fuzzing, argv[1] is the input file)
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

    // Create a sockaddr structure for passing to ares_parse_a_reply
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);  // Use localhost as an example

    // Result struct for the reply
    struct ares_addrinfo *result;

    // Parse the DNS reply using the correct function signature (5 arguments)
    ares_parse_a_reply(buffer, length, (struct sockaddr *)&addr, sizeof(addr), &result);

    // Free the result
    ares_freeaddrinfo(result);
    delete[] buffer;

    // Clean up c-ares library
    ares_library_cleanup();
    return 0;
}
