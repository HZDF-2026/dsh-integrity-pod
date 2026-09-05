// prereg.h — dsh-integrity-prereg: append-only hash-chained pre-registrations.
#ifndef dship_PREREG_H
#define dship_PREREG_H

#include "jsjson.h"

#include <string>
#include <vector>
#include <stdexcept>

namespace dship {

struct PreregRegisterArgs {
    std::string claim;
    bool hasBoundary = false;
    double boundary = 0;
    bool hasDirection = false;
    std::string direction;
    bool hasTolerance = false;
    double tolerance = 0;
    std::string decisionRules;
    std::string store;  // empty -> ".integrity/prereg.jsonl"
};

// Returns the JSON.stringify of the tool result (exact key order). Throws
// std::runtime_error with the plugin's message on invalid input.
std::string preregRegister(const PreregRegisterArgs& args);

std::string preregList(const std::string& store);

std::string preregVerify(const std::string& store);

// Shared with adjudicate: full-chain check over already-loaded records.
bool preregChainVerified(const std::vector<Json>& records);

}  // namespace dship

#endif  // dship_PREREG_H
