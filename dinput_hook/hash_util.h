//
// sha256, the way the content store and the records both need it: over bytes already in memory,
// as lowercase hex. Windows CNG does the work, so there is no crypto implementation in the tree.
//
#pragma once

#include <cstddef>
#include <string>

bool sha256_hex(const void *data, size_t size, std::string *out);
