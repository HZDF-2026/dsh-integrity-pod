// sha256.h — FIPS 180-4 SHA-256, matching Node's crypto.createHash('sha256').
#ifndef dship_SHA256_H
#define dship_SHA256_H

#include <cstdint>
#include <string>

namespace dship {

// Hex digest (lowercase) of the byte string, like digest('hex').
std::string sha256Hex(const std::string& data);

}  // namespace dship

#endif  // dship_SHA256_H
