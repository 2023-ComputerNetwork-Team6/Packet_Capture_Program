#ifndef NETWORK_RAW_SOCKET_SSH_H
#define NETWORK_RAW_SOCKET_SSH_H

#include <stdint-gcc.h>

//chat gpt
struct sshHeader{
    uint32_t packet_length;     // Total length of the packet, excluding this field
    uint8_t padding_length;     // Length of padding (in bytes)
    uint8_t payload_type;       // Message code
    // Additional fields for specific packet types
    // For example, sequence number, padding, MAC, etc.
    // ...

    // Additional fields for some packet types
    // ...

    // Variable-length fields
    uint8_t variable_data[1];
};

#endif NETWORK_RAW_SOCKET_SSH_H