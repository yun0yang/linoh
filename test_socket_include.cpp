// Test socket.hpp include chain
#include "linoh/net/socket.hpp"

// Just use something from socket.hpp to force full parsing
void test_func() {
    linoh::net::RemoteState* rs = nullptr;
    (void)rs;
}
